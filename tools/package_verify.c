/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zclassic23-package-verify — the EXTERNAL ZCODE package verifier (slice 6).
 * This is a SEPARATE program from the node: the Z23 node itself NEVER * compiles or executes downloaded code. Given a package root, this program
 * loads the signed release envelope, the manifest, the CAS chunks, and the
 * slice-5 declarative recipe from an EXPLICIT package store directory, then
 * builds and tests the package under confinement and writes ONE signed
 * attestation (lib/vcs/package_attest.*) into the store's attestations/
 * directory. Quorum (>=2 approved independent keys) is evaluated elsewhere
 * (the node's `zcode package verify` command); this program only ever
 * produces one attestation signed by one verifier key.
 *
 *   zclassic23-package-verify <package-root-hex> --store=<dir> --key=<file>
 *                             [--work=<dir>] [--require-full-isolation]
 *
 * Isolation contract (per spawned child — every compile, link, and test
 * run):
 *   - no network: a seccomp deny-list kills the whole socket family
 *     (socket/connect/bind/listen/accept, send, recv, socketpair and
 *     their variants), plus ptrace/process_vm_*, mount/namespace escape,
 *     kernel modules, keyrings, bpf, perf, and open_by_handle_at. execve
 *     and fork/clone stay allowed:
 *     gcc is a driver that must exec cc1/as/ld, and pthread tests need
 *     clone — every exec'd image inherits no_new_privs + seccomp +
 *     Landlock + rlimits, so this is not an escape.
 *   - filesystem scoping: a Landlock domain grants ONLY the materialized
 *     source tree (read), the temp build dir (read/write/create/execute),
 *     the host toolchain (/usr, /lib, /lib64, /etc read+execute),
 *     /dev/null + /dev/urandom, and the child's OWN /proc/self (read —
 *     compiler-rt re-reads /proc/self/environ for its runtime flags; deny
 *     it and ASan falls back to DEFAULT flags, resurrecting LeakSanitizer,
 *     which then dies stop-the-world). Wallet paths, node datadirs, SSH
 *     keys, and credentials are simply never granted — denial is the
 *     default.
 *   - environment hygiene: every child runs with a SCRUBBED environment
 *     (clearenv + PATH/LC_ALL + the explicit TMPDIR/ASAN_OPTIONS/
 *     UBSAN_OPTIONS pairs) — an operator shell carries credentials
 *     (API keys, tokens) that untrusted package code must never see.
 *     LeakSanitizer is deliberately OFF (detect_leaks=0): its
 *     stop-the-world needs ptrace + cross-process /proc access, both
 *     denied by this confinement; ASan memory-error and UBSan checks are
 *     unaffected.
 *   - resource limits: RLIMIT_AS = the recipe's maximum_memory_bytes,
 *     RLIMIT_CPU = the recipe's maximum_test_seconds, plus
 *     NPROC/FSIZE/NOFILE/CORE caps (NPROC as a margin over the uid's
 *     current task count — RLIMIT_NPROC is session-wide per uid), and a
 *     parent-enforced wall-clock deadline (SIGKILL) on every child. Sanitizer (ASan/UBSan) runs are
 *     the ONE exception: ASan's multi-terabyte shadow address space makes
 *     RLIMIT_AS meaningless, so the AS limit is lifted for those runs only
 *     (CPU/wall/proc/file limits still bind; the plain run is the
 *     resource-bound one — documented in the attestation's detail text
 *     when it matters).
 *   - the recipe is the ONLY build input: package Makefiles, configure
 *     scripts, and every other downloaded file are never executed. Only
 *     recipe.sources / recipe.test_sources are compiled, with exactly the
 *     recipe's include dirs, defines, and allowed libraries (v1:
 *     libc/libm/pthread).
 *   - the materialized source tree is read-only (files 0444, dirs 0555);
 *     builds write only to the separate build dir; every produced binary
 *     and object is DELETED with the temp tree after the attestation is
 *     written (success or failure).
 *
 * Degraded mode: where the kernel offers no Landlock, children still run
 * under no_new_privs + seccomp + rlimits (network and resources stay
 * bound) but the filesystem is NOT scoped — the attestation then carries
 * isolation=degraded and this program prints a loud warning. Operators who
 * refuse degraded attestations pass --require-full-isolation, which fails
 * closed (no attestation is written). The quorum policy and the `zcode
 * package verify` report surface the isolation level of every attestation.
 *
 * Key file: 64 lowercase/uppercase hex chars (one secp256k1 secret), in a
 * regular file with no group/other permission bits. The key NEVER leaves
 * this process; signing uses the libsecp256k1 RFC6979 nonce function and
 * the compact low-S form the attestation codec enforces.
 *
 * Exit codes: 0 attestation written (whatever its verdict — a build-fail
 * attestation is still a successful verification run); 2 usage; 3 the
 * store/release/manifest/recipe/chunks could not be loaded or the package
 * is incomplete; 4 --require-full-isolation on a no-Landlock kernel; 5 an
 * internal/sandbox failure (nothing is signed); 6 emit mode with
 * --reproduce-against: the build does NOT reproduce the reference
 * build-report byte-for-byte (a verdict, not an internal failure — the
 * mismatch rule and detail are on stderr). */

/* clearenv(3) for the child environment scrub (glibc; the project builds
 * with strict -D_POSIX_C_SOURCE=200809L, so opt in like lib/test does). */
#define _DEFAULT_SOURCE

#include "vcs/package_attest.h"
#include "vcs/build_action.h"
#include "vcs/build_artifact_manifest.h"
#include "vcs/package_build.h"
#include "vcs/fastobj.h"
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/package_reproduce.h"
#include "vcs/zcode_dev.h"
#include "vcs/package_release.h"

#include "base/hex.h"
#include "config/c23_commons_build_profile.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "platform/clock.h"
#include "platform/os_proc.h"
#include "platform/process_compat.h"
#include "platform/os_sandbox.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <secp256k1.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PV_LOG "package-verify"

/* The node-wide shutdown flag lives in src/main.c, which is not linked
 * into this standalone binary; the app TUs in ALL_SRCS reference it
 * extern, so every tool main defines it (tools/bot.c precedent). */
volatile sig_atomic_t g_shutdown_requested = 0;

/* Child wall-clock budgets. The test-run budget comes from the recipe;
 * compiles and links get fixed caps (the recipe bounds tests, not the
 * compiler's own speed). */
#define PV_COMPILE_TIMEOUT_MS 120000
#define PV_LINK_TIMEOUT_MS 120000
/* Fixed compile-time resource caps (the recipe bounds the TEST run). */
#define PV_COMPILE_AS_BYTES (UINT64_C(4) * 1024u * 1024u * 1024u)
#define PV_COMPILE_FSIZE_BYTES (UINT64_C(256) * 1024u * 1024u)
/* Process budgets. These constants are the SUBTREE budget of one confined
 * action: how many processes that action's own child tree may hold at once.
 *
 * They are NOT the value installed on RLIMIT_NPROC. RLIMIT_NPROC is charged
 * per REAL UID, kernel-wide, so it cannot express a subtree budget at all:
 * an absolute value bounds the subtree at (value − the uid's concurrent task
 * count), and rebasing it on a snapshot, (task count at time T) + margin, is
 * the same load-dependent quantity sampled a moment earlier — every task the
 * uid starts between T and the child's fork silently eats the margin. A
 * 32-worker suite starts and reaps hundreds of tasks a second, so a 16-task
 * margin bought nothing and the compiler died with
 * "posix_spawn: Resource temporarily unavailable" reported as a COMPILE
 * ERROR. See platform/os_sandbox.h "process budget".
 *
 * So the budget below is enforced where it is actually meaningful — by the
 * parent, as a census of the child's own process GROUP (a group id is
 * inherited across fork and survives double-fork reparenting) — and
 * RLIMIT_NPROC is demoted to a static absolute backstop that never samples
 * load. Whether the host has process table left at all is a separate
 * ADMISSION decision, reported as a wedge, never as a build verdict. */
#define PV_COMPILE_NPROC 256u
/* The absolute RLIMIT_NPROC backstop, clamped down only by the uid's static
 * NPROC hard limit (host CONFIGURATION, which does not move while a suite
 * runs — not host LOAD). Deliberately generous: it exists so a runaway
 * subtree cannot exhaust the machine between two censuses, not as the
 * action's budget. */
#define PV_NPROC_BACKSTOP 65536u
/* Process-table headroom an action needs beyond its own subtree budget
 * before it is admitted at all (pipes, the fork itself, the exec). */
#define PV_NPROC_LAUNCH_SLACK 16u
/* How often the parent censuses the child's process group, in the 1 ms
 * ticks of its drain loop. */
#define PV_NPROC_CENSUS_TICKS 20
/* Exit code for "this host had no process table left" at the zbuild entry
 * points. Distinct from 5 (internal/sandbox failure) and from every build
 * verdict: EX_TEMPFAIL, i.e. retry this action, do not blame the input. */
#define PV_EXIT_RESOURCE_WEDGE 75
#define PV_COMPILE_NOFILE 1024u
/* The exact one-TU build action has a much smaller, action-keyed budget than
 * the general package verifier (which may run multi-source compiler and
 * sanitizer matrices). Keep the two policies distinct. */
/* cc forks cc1 and as; 16 concurrent processes is generous for one TU. */
#define PV_ZBUILD_COMPILE_NPROC 16u
#define PV_ZBUILD_COMPILE_NOFILE 64u
/* Test-run fixed caps beyond the recipe's AS/CPU. */
#define PV_TEST_FSIZE_BYTES (UINT64_C(64) * 1024u * 1024u)
#define PV_TEST_NPROC 64u
#define PV_TEST_NOFILE 64u
/* Capture bounds. */
#define PV_STDOUT_CAP 2048u
#define PV_STDERR_CAP 4096u
/* ASan/UBSan marker exit codes (set via *_OPTIONS in the child env). */
#define PV_ASAN_EXIT 99
#define PV_UBSAN_EXIT 98
/* Child internal failures (never a verdict). */
#define PV_CHILD_SANDBOX_FAIL 125
#define PV_CHILD_SECCOMP_FAIL 126
#define PV_CHILD_EXEC_FAIL 127

#define PV_ZBUILD_TEST_EVIDENCE_BYTES 84u
#define PV_ZBUILD_TEST_TIMEOUT_MS 120000
#define PV_ZBUILD_FUZZ_EVIDENCE_BYTES 96u

/* Emit-mode bounds. The archive/header install carries the same
 * canonical-path grammar as the manifest, so an emitted path can never
 * become a filesystem escape. */
#define PV_EMIT_MAX_DEPS 64u

/* One locked dependency the target builds against: its package root (which
 * the build receipt commits) and its already-installed directory, whose
 * include/ is granted READ-ONLY to the compile children and whose static
 * archives under lib/ are appended to the link line. */
struct pv_emit_dep {
    uint8_t root[32];
    char install_dir[2048];
    char include_dir[2100];
};

static void pv_usage(FILE *out)
{
    fprintf(out,
        "usage: zclassic23-package-verify <package-root-hex> --store=<dir>\n"
        "           --key=<file> [--work=<dir>] [--require-full-isolation]\n"
        "   or: zclassic23-package-verify <package-root-hex> --store=<dir>\n"
        "           --emit=<dir> --lock-root=<64hex> [--dep=<64hex>,<dir>]...\n"
        "           [--reproduce-against=<build-report>] [--plan=<file>]\n"
        "           [--work=<dir>] [--require-full-isolation]\n"
        "   or: zclassic23-package-verify <candidate-source-root-hex>\n"
        "           --zbuild-package-source=<abs-dir>\n"
        "           --zbuild-package-recipe=<abs-file>\n"
        "           --zbuild-package-name=<publisher/package>\n"
        "           --zbuild-package-profile=<quick|standard>\n"
        "           --zbuild-package-max-cpu-seconds=<1..600>\n"
        "           --emit=<abs-dir> --lock-root=<64hex>\n"
        "           [--dep=<64hex>,<installed-dir>]...\n"
        "           [--plan=<file>] [--fast-cache=<dir>]\n"
        "           [--allow-testless-standard]\n"
        "           --require-full-isolation\n"
        "   or: zclassic23-package-verify --zbuild-input=<abs>/unit.i\n"
        "           --zbuild-output=<abs>/unit.o --require-full-isolation\n"
        "   or: zclassic23-package-verify --zbuild-test-input=<abs>/test.bin\n"
        "           --zbuild-test-output=<abs>/test.evidence.v1\n"
        "           --require-full-isolation\n"
        "   or: zclassic23-package-verify --zbuild-fuzz-input=<abs>/fuzz.bin\n"
        "           --zbuild-fuzz-output=<abs>/fuzz.evidence.v1\n"
        "           --zbuild-fuzz-seeds=<1..4096>\n"
        "           --zbuild-fuzz-cpu-seconds=<1..600>\n"
        "           --zbuild-fuzz-memory-bytes=<1..2147483648>\n"
        "           --zbuild-fuzz-output-bytes=<1..67108864>\n"
        "           --require-full-isolation\n"
        "\n"
        "--emit is INSTALL-BUILD mode (the ZCODE add lifecycle): the same\n"
        "confined build+test runs, but instead of signing an attestation the\n"
        "run archives the recipe's non-test objects into <dir>/lib/lib<pkg>.a,\n"
        "copies the recipe's public headers under <dir>/include/, and writes\n"
        "the canonical build receipt (vcs/package_build.h) to\n"
        "<dir>/build-report. NOTHING is signed in this mode and --key is\n"
        "refused: the caller is the node's own lifecycle service, which\n"
        "independently RE-HASHES every emitted file against the receipt\n"
        "before installing it. --lock-root pins the dependency lock the\n"
        "receipt commits; each --dep names a locked dependency root and its\n"
        "install dir, whose include/ is granted read-only to the compile\n"
        "children and whose lib/*.a archives join the link line.\n"
        "The --zbuild-package-* form is the candidate proof action. Its\n"
        "source tree and canonical recipe are materialized by the parent\n"
        "from immutable ZVCS CAS; it accepts no prebuilt executable and\n"
        "emits the same canonical build-report without requiring a signed\n"
        "release for the not-yet-published candidate.\n"
        "--reproduce-against is the THIRD-PARTY BIT-IDENTICAL REPRODUCTION\n"
        "check (the headline ZCODE acceptance signal): after the emit build\n"
        "writes its own build-report, the reference build-report named here\n"
        "(the publisher's or another verifier's) is compared against it\n"
        "byte-for-byte — same package/recipe/lock commitments and an\n"
        "identical output set (path, SHA3-256, byte count). MATCH prints on\n"
        "stdout; any divergence prints a loud REPRODUCTION MISMATCH naming\n"
        "the first diverging rule on stderr and the exit code is 6.\n"
        "--plan=<file> (emit modes only) additionally writes the EXACT\n"
        "dependency plan (zcl.dep_plan.v1): before any real compile, every\n"
        "recipe source TU is preprocessed under the same confinement with\n"
        "the exact compile argv plus -E -MD -MF, and the plan records the\n"
        "depfile closure (path, SHA3-256, bytes, class), the preprocessed\n"
        "unit digest, the macro-environment digest (gcc -E -dM), the exact\n"
        "argv, and the toolchain capsule root. Semantic facts gcc14 cannot\n"
        "prove (macro EXPANSION usage, declarations/types used) are marked\n"
        "not_claimed, never guessed. A plan failure aborts the run before\n"
        "any build output; the plan is local evidence, not an admission.\n");
    fprintf(out,
        "--fast-cache=<dir> (candidate mode only) enables the per-TU object\n"
        "cache (zcl.fastobj.v1). Each recipe source TU is preprocessed once\n"
        "with the exact compile argv; the cache key binds the toolchain\n"
        "capsule root, target, profile, the @-token-normalized exact argv,\n"
        "and the preprocessed-unit SHA3-256. A hit is re-verified byte-for-\n"
        "byte against its sidecar before reuse (hardlink-else-copy into the\n"
        "work tree); a torn entry, sidecar mismatch, or materialization\n"
        "mismatch fails the run closed. Cached objects are admission=\n"
        "local_candidate only — never an attestation or admission input.\n");
    fprintf(out,
        "\n"
        "Builds and tests one ZCODE package under confinement (seccomp +\n"
        "rlimits + Landlock where the kernel offers it) following ONLY the\n"
        "slice-5 declarative recipe, then writes one secp256k1-signed\n"
        "attestation into <store>/attestations/<attestation-id-hex>.\n"
        "The node never compiles downloaded code; this separate program is\n"
        "the only place compilation happens. Produced binaries are deleted\n"
        "after the attestation is written. --key names a 0600/0400 file\n"
        "holding one 64-hex secp256k1 secret. --work chooses the parent of\n"
        "the temp build tree (default: $TMPDIR or /tmp). On a kernel\n"
        "without Landlock the run is DEGRADED (no filesystem scoping; the\n"
        "attestation says isolation=degraded) unless\n"
        "--require-full-isolation is given, which fails closed.\n");
}

static bool pv_source_path_is(const char *root, const char *path,
                              bool want_dir)
{
    char full[4200], resolved[4200];
    int n = snprintf(full, sizeof(full), "%s/%s", root, path);
    struct stat st;
    size_t rl = strlen(root);
    if (n <= 0 || (size_t)n >= sizeof(full) || lstat(full, &st) != 0 ||
        (want_dir ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode)) ||
        !realpath(full, resolved) || strncmp(resolved, root, rl) != 0 ||
        resolved[rl] != '/')
        return false;
    return true;
}

static bool pv_recipe_files_in_source(
    const struct vcs_package_recipe *recipe, const char *root,
    char *detail, size_t detail_cap)
{
    const struct vcs_package_recipe_strings *files[] = {
        &recipe->public_headers, &recipe->sources, &recipe->test_sources,
    };
    const char *labels[] = { "public_header", "source", "test_source" };
    for (size_t k = 0; k < sizeof(files) / sizeof(files[0]); k++)
        for (size_t i = 0; i < files[k]->count; i++)
            if (!pv_source_path_is(root, files[k]->items[i], false)) {
                (void)snprintf(detail, detail_cap, "%s:%s", labels[k],
                               files[k]->items[i]);
                return false;
            }
    for (size_t i = 0; i < recipe->include_dirs.count; i++)
        if (!pv_source_path_is(root, recipe->include_dirs.items[i], true)) {
            (void)snprintf(detail, detail_cap, "include_dir:%s",
                           recipe->include_dirs.items[i]);
            return false;
        }
    return true;
}

/* ── small utilities ────────────────────────────────────────────────── */

static bool pv_mkdir_p(const char *path, mode_t mode)
{
    char buf[4096];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(buf))
        return false;
    memcpy(buf, path, len + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, mode) != 0 && errno != EEXIST)
            return false;
        *p = '/';
    }
    return mkdir(buf, mode) == 0 || errno == EEXIST;
}

static bool pv_rm_rf(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT;
    if (!S_ISDIR(st.st_mode))
        return unlink(path) == 0;
    DIR *dir = opendir(path);
    if (!dir)
        return false;
    bool ok = true;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char child[4096];
        int n = snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        if (n <= 0 || (size_t)n >= sizeof(child)) {
            ok = false;
            continue;
        }
        if (!pv_rm_rf(child))
            ok = false;
    }
    closedir(dir);
    if (rmdir(path) != 0)
        ok = false;
    return ok;
}

/* Read a whole file bounded by cap (NULL on any failure/oversize). */
static uint8_t *pv_read_file(const char *path, size_t cap, size_t *out_len)
{
    *out_len = 0;
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (uint64_t)st.st_size > cap)
        return NULL;
    size_t len = (size_t)st.st_size;
    uint8_t *buf = zcl_malloc(len, "pv_read_file");
    if (!buf)
        return NULL;
    FILE *f = fopen(path, "rb");
    if (!f) {
        free(buf);
        return NULL;
    }
    if (fread(buf, 1, len, f) != len) {
        fclose(f);
        free(buf);
        return NULL;
    }
    fclose(f);
    *out_len = len;
    return buf;
}

/* Durable write beside the destination: tmp, fsync, atomic rename (the
 * store's own discipline — a torn attestation is never a valid object). */
static bool pv_atomic_write(const char *path, const uint8_t *data,
                            size_t data_len)
{
    char tmp[4096];
    int tn = snprintf(tmp, sizeof(tmp), "%s.zvtmp.%ld", path,
                      (long)getpid());
    if (tn <= 0 || (size_t)tn >= sizeof(tmp))
        return false;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    size_t off = 0;
    while (off < data_len) {
        ssize_t w = write(fd, data + off, data_len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            unlink(tmp);
            return false;
        }
        off += (size_t)w;
    }
    if (fsync(fd) != 0 || close(fd) != 0 || rename(tmp, path) != 0) {
        close(fd);
        unlink(tmp);
        return false;
    }
    return true;
}

/* ── the sandboxed child runner ─────────────────────────────────────── */

/* The verifier child deny-set: the whole socket family (network denial),
 * cross-process memory, mount/namespace escape, kernel modules, keyrings,
 * bpf, perf, and handle-based opens. execve/fork/clone stay ALLOWED —
 * gcc must exec cc1/as/ld and pthread tests need clone; every exec'd
 * image inherits the full confinement. Guarded __NR_* like the
 * os_sandbox session set. */
#if defined(__linux__)
static const int g_pv_child_denied[] = {
    __NR_socket,
#ifdef __NR_socketcall
    __NR_socketcall,
#endif
    __NR_socketpair, __NR_connect, __NR_bind, __NR_listen,
    __NR_accept, __NR_accept4,
    __NR_sendto, __NR_recvfrom, __NR_sendmsg, __NR_recvmsg,
    __NR_shutdown, __NR_setsockopt, __NR_getsockopt,
    __NR_getsockname, __NR_getpeername,
    __NR_ptrace, __NR_process_vm_readv, __NR_process_vm_writev,
    __NR_mount, __NR_umount2, __NR_pivot_root, __NR_setns, __NR_unshare,
    __NR_bpf, __NR_kexec_load, __NR_kexec_file_load,
    __NR_init_module, __NR_finit_module, __NR_delete_module,
    __NR_perf_event_open,
    __NR_add_key, __NR_request_key, __NR_keyctl,
    __NR_open_by_handle_at,
};
#define PV_CHILD_DENIED_COUNT \
    (sizeof(g_pv_child_denied) / sizeof(g_pv_child_denied[0]))
#else
static const int g_pv_child_denied[] = { 0 };
#define PV_CHILD_DENIED_COUNT 0u
#endif

struct pv_run {
    bool launched;     /* fork/pipe machinery worked */
    bool exited;       /* child exited (vs signaled/timed out) */
    int exit_code;
    int term_signal;
    bool timed_out;
    bool sandbox_fail; /* the child could not arm its own confinement */
    /* Process-accounting outcomes. These are DISJOINT from every build
     * verdict above: `headroom_exhausted` is the HOST being out of process
     * table for this uid (a wedge — retry it), `budget_exceeded` is the
     * confined subtree spending more processes than the action declares (a
     * defect in the input — never retry it). A build error is neither. */
    bool headroom_exhausted;
    bool budget_exceeded;
    uint64_t nproc_backstop;   /* absolute RLIMIT_NPROC actually installed */
    uint64_t uid_tasks;        /* real uid's task count at admission       */
    uint64_t subtree_budget;   /* the action's declared process budget     */
    uint64_t subtree_peak;     /* largest census of the child's group      */
    bool stdout_truncated;
    bool stderr_truncated;
    size_t stdout_len;
    size_t stderr_len;
    char stdout_buf[PV_STDOUT_CAP];
    char stderr_buf[PV_STDERR_CAP];
};

/* One line naming a process-accounting outcome, or NULL when the run had
 * none. Callers print this INSTEAD of a build-failure line so a wedge and a
 * real defect never share a message (or, at the zbuild entry points, an exit
 * code — see PV_EXIT_RESOURCE_WEDGE). */
static const char *pv_run_process_failure(const struct pv_run *r)
{
    if (!r) return NULL;
    if (r->headroom_exhausted) return "process-headroom-exhausted";
    if (r->budget_exceeded) return "process-budget-exceeded";
    return NULL;
}

/* gcc reports a fork/posix_spawn EAGAIN as its own FATAL ERROR on stderr, so
 * a host that ran out of process table for this uid is otherwise
 * indistinguishable from source the compiler rejected — which is exactly how
 * this defect hid. Recognise it and re-class the run.
 *
 * Applied ONLY where the child is the FIXED trusted compiler. Untrusted test
 * code must never be able to type this string on stderr and have its failure
 * re-labelled a host wedge. */
static bool pv_stderr_is_process_exhaustion(const char *stderr_buf)
{
    return stderr_buf &&
        (strstr(stderr_buf, "Resource temporarily unavailable") != NULL ||
         strstr(stderr_buf, "fork: retry:") != NULL);
}

/* If `run` failed on process accounting, print ONE line naming which of the
 * two it was — with the installed backstop, the uid task count at admission,
 * the uid task count now, and the subtree budget and peak — and return the
 * exit code for it. Returns 0 when the run had no process-accounting
 * failure, so a caller writes:
 *
 *     int wedged = pv_report_process_failure(&run, "zbuild-error", true);
 *     if (wedged) return wedged;
 *
 * The two outcomes never share an exit code: a HOST out of process table is
 * PV_EXIT_RESOURCE_WEDGE (retry the action), a SUBTREE over its declared
 * budget is 5 (the input is at fault). Set `trusted_child` only where the
 * child is the fixed compiler — see pv_stderr_is_process_exhaustion. */
static int pv_report_process_failure(const struct pv_run *run,
                                     const char *prefix, bool trusted_child)
{
    if (!run || !prefix) return 0;
    const char *cls = pv_run_process_failure(run);
    if (!cls && trusted_child && run->nproc_backstop && !run->timed_out &&
        !run->sandbox_fail && run->exited && run->exit_code != 0 &&
        pv_stderr_is_process_exhaustion(run->stderr_buf))
        cls = "process-headroom-exhausted";  /* the backstop itself bit */
    if (!cls) return 0;
    fprintf(stdout,
            "%s=%s nproc_backstop=%llu uid_tasks_at_admission=%llu "
            "uid_tasks_now=%llu subtree_budget=%llu subtree_peak=%llu "
            "diagnostics=%.256s\n",
            prefix, cls,
            (unsigned long long)run->nproc_backstop,
            (unsigned long long)run->uid_tasks,
            (unsigned long long)os_sandbox_uid_task_count(),
            (unsigned long long)run->subtree_budget,
            (unsigned long long)run->subtree_peak,
            run->stderr_buf);
    return run->budget_exceeded ? 5 : PV_EXIT_RESOURCE_WEDGE;
}

struct pv_perf_metrics {
    uint64_t processes;
    uint64_t compiler_processes;
    uint64_t test_processes;
    uint64_t other_processes;
    uint64_t child_wall_us;
    uint64_t child_cpu_us;
    uint64_t compiler_wall_us;
    uint64_t test_wall_us;
};

static struct pv_perf_metrics g_pv_perf;
static uint64_t g_pv_cpu_budget_us;
static uint64_t g_pv_cpu_used_us;

static uint64_t pv_rusage_cpu_us(const struct rusage *usage)
{
    return usage
        ? (uint64_t)usage->ru_utime.tv_sec * UINT64_C(1000000) +
          (uint64_t)usage->ru_utime.tv_usec +
          (uint64_t)usage->ru_stime.tv_sec * UINT64_C(1000000) +
          (uint64_t)usage->ru_stime.tv_usec
        : 0;
}

static void pv_perf_record(const char *program, uint64_t elapsed_us)
{
    const char *base = program ? strrchr(program, '/') : NULL;
    base = base ? base + 1 : program;
    g_pv_perf.processes++;
    g_pv_perf.child_wall_us += elapsed_us;
    if (base && (strstr(base, "gcc") || strstr(base, "clang") ||
                 strcmp(base, "cc") == 0)) {
        g_pv_perf.compiler_processes++;
        g_pv_perf.compiler_wall_us += elapsed_us;
    } else if (base && (strstr(base, "test") || strstr(base, "fuzz"))) {
        g_pv_perf.test_processes++;
        g_pv_perf.test_wall_us += elapsed_us;
    } else {
        g_pv_perf.other_processes++;
    }
}

/* Landlock grant set for every verifier child: the materialized source
 * (read), the build dir (full), the host toolchain (read+execute), and
 * the two harmless /dev nodes. Anything else — wallet, datadir, SSH — is
 * denied by default. */
static size_t pv_child_grants(const char *src_dir, const char *build_dir,
                              const struct pv_emit_dep *deps, size_t dep_count,
                              struct os_sandbox_path_rule *rules,
                              size_t cap)
{
    size_t n = 0;
    if (cap < 10u + dep_count)
        return 0;
    rules[n++] = (struct os_sandbox_path_rule){
        .path = src_dir, .allow_read = true };
    rules[n++] = (struct os_sandbox_path_rule){
        .path = build_dir, .allow_read = true, .allow_write = true,
        .allow_execute = true, .allow_create = true };
    rules[n++] = (struct os_sandbox_path_rule){
        .path = "/usr", .allow_read = true, .allow_execute = true };
    rules[n++] = (struct os_sandbox_path_rule){
        .path = "/lib", .allow_read = true, .allow_execute = true };
    struct stat st;
    if (stat("/lib64", &st) == 0)
        rules[n++] = (struct os_sandbox_path_rule){
            .path = "/lib64", .allow_read = true, .allow_execute = true };
    rules[n++] = (struct os_sandbox_path_rule){
        .path = "/etc", .allow_read = true };
    /* The child's OWN /proc/self only: compiler-rt (ASan/UBSan) re-reads
     * /proc/self/environ for its runtime flags and /proc/self/maps for the
     * shadow layout; denying it makes the runtimes fall back to DEFAULT
     * flags (LeakSanitizer on), which then dies stop-the-world. The child
     * environment is scrubbed (see pv_run_child), so this exposes nothing
     * beyond the child's own process. */
    rules[n++] = (struct os_sandbox_path_rule){
        .path = OS_SANDBOX_PROC_SELF_PATH, .allow_read = true };
    rules[n++] = (struct os_sandbox_path_rule){
        .path = "/dev/null", .allow_read = true, .allow_write = true };
    rules[n++] = (struct os_sandbox_path_rule){
        .path = "/dev/urandom", .allow_read = true };
    /* Locked dependencies: READ ONLY, and only the install dirs the caller
     * named (headers to compile against, archives to link). Never write,
     * never execute — a dependency is data to this build, not a program. */
    for (size_t i = 0; i < dep_count; i++)
        rules[n++] = (struct os_sandbox_path_rule){
            .path = deps[i].install_dir, .allow_read = true };
    return n;
}

/* This process's own current mapped size (RLIMIT_AS's accounting unit).
 * fork() gives the child the same mapping, so a limit set to the recipe's
 * raw byte budget alone starves the not-yet-exec'd child of the address
 * space this verifier binary's own text/data/bss already occupy — the
 * child dies with SIGSEGV growing its stack during rlimit/Landlock/seccomp
 * setup, before it ever reaches execve(). Best-effort: an unreadable
 * VmSize yields 0. */
static uint64_t pv_process_vsize_bytes(void)
{
    struct os_proc_mem mem;
    if (!os_proc_mem_read(&mem) || mem.vsize_bytes < 0)
        return 0;
    return (uint64_t)mem.vsize_bytes;
}


/* Fork and run argv[0] confined. The child: stderr/stdout captured,
 * optional chdir, rlimits, no_new_privs, Landlock (when landlock=true),
 * the seccomp deny-set, then execvp. The parent enforces the wall-clock
 * deadline with SIGKILL. env_pairs is a NULL-terminated flat array of
 * "NAME=value" strings applied in the child (or NULL). */
static struct pv_run pv_run_child(const char *const argv[],
                                  const char *cwd,
                                  const struct os_sandbox_rlimits *limits,
                                  bool landlock,
                                  const struct os_sandbox_path_rule *rules,
                                  size_t n_rules,
                                  const char *const env_pairs[],
                                  int timeout_ms)
{
    struct pv_run r;
    memset(&r, 0, sizeof(r));
    if (g_pv_cpu_budget_us && g_pv_cpu_used_us >= g_pv_cpu_budget_us) {
        r.launched = true;
        r.timed_out = true;
        (void)snprintf(r.stderr_buf, sizeof(r.stderr_buf),
                       "aggregate CPU budget exhausted");
        r.stderr_len = strlen(r.stderr_buf);
        return r;
    }
    int64_t perf_started_ns = clock_now_monotonic_ns();
    /* AS is rebased onto this very process's own mapping (see
     * pv_process_vsize_bytes) — a fork child starts from that same mapping,
     * so the recipe's byte budget must land on top of it, not replace it.
     *
     * NPROC is NOT rebased. The caller's nproc is the action's SUBTREE
     * budget, enforced below by a census of the child's process group; the
     * value installed on RLIMIT_NPROC is the static PV_NPROC_BACKSTOP
     * (clamped only by the uid's hard limit). See the PV_COMPILE_NPROC
     * comment for why any load-sampled value is a coin flip here. */
    struct os_sandbox_rlimits rebased;
    if (limits && (limits->nproc != OS_SANDBOX_RLIMIT_KEEP ||
                   limits->as_bytes != OS_SANDBOX_RLIMIT_KEEP ||
                   g_pv_cpu_budget_us != 0)) {
        rebased = *limits;
        if (limits->nproc != OS_SANDBOX_RLIMIT_KEEP) {
            struct os_sandbox_process_budget budget =
                os_sandbox_process_budget_live(
                    PV_NPROC_BACKSTOP,
                    limits->nproc + PV_NPROC_LAUNCH_SLACK);
            r.subtree_budget = limits->nproc;
            r.nproc_backstop = budget.ceiling;
            r.uid_tasks = budget.uid_tasks;
            if (!budget.admitted) {
                /* The HOST is out of process table for this uid. Refusing
                 * here — before the fork — is what keeps this out of the
                 * child's exit status, where it would be indistinguishable
                 * from the compiler rejecting the input. */
                r.headroom_exhausted = true;
                (void)snprintf(r.stderr_buf, sizeof(r.stderr_buf),
                    "process-headroom-exhausted: uid tasks=%llu of "
                    "RLIMIT_NPROC backstop=%llu (hard=%llu), headroom=%llu "
                    "< required=%llu for a subtree budget of %llu",
                    (unsigned long long)budget.uid_tasks,
                    (unsigned long long)budget.ceiling,
                    (unsigned long long)budget.hard,
                    (unsigned long long)budget.headroom,
                    (unsigned long long)budget.required,
                    (unsigned long long)limits->nproc);
                r.stderr_len = strlen(r.stderr_buf);
                return r;
            }
            rebased.nproc = budget.ceiling;
        }
        if (limits->as_bytes != OS_SANDBOX_RLIMIT_KEEP)
            rebased.as_bytes = pv_process_vsize_bytes() + limits->as_bytes;
        if (g_pv_cpu_budget_us) {
            uint64_t remaining = g_pv_cpu_budget_us - g_pv_cpu_used_us;
            uint64_t seconds = (remaining + UINT64_C(999999)) /
                               UINT64_C(1000000);
            if (rebased.cpu_seconds == OS_SANDBOX_RLIMIT_KEEP ||
                rebased.cpu_seconds > seconds)
                rebased.cpu_seconds = seconds;
        }
        limits = &rebased;
    }
    int out_pipe[2] = { -1, -1 };
    int err_pipe[2] = { -1, -1 };
    if (pipe(out_pipe) != 0 || pipe(err_pipe) != 0)
        return r;
    pid_t pid = fork();
    if (pid < 0) {
        close(out_pipe[0]); close(out_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        return r;
    }
    if (pid == 0) {
        /* Child: single-threaded standalone CLI, so the pre-exec calls
         * below are safe here (no other thread holds a lock). */
        /* Own process group FIRST: it is what makes the action's process
         * budget enforceable (the parent censuses this group) and what makes
         * the deadline kill reach the WHOLE subtree instead of just this
         * process. A group id is inherited across fork and is not lost when a
         * grandchild is reparented, so nothing in the tree can escape it.
         * Raced with the parent's identical call so neither ordering loses. */
        (void)setpgid(0, 0);
        close(out_pipe[0]);
        close(err_pipe[0]);
        (void)dup2(out_pipe[1], STDOUT_FILENO);
        (void)dup2(err_pipe[1], STDERR_FILENO);
        if (cwd && chdir(cwd) != 0)
            _exit(PV_CHILD_EXEC_FAIL);
        /* Scrub the inherited environment: the operator's shell env can
         * carry credentials (API keys, tokens) that untrusted package code
         * must never see. The child gets a minimal base plus the caller's
         * explicit pairs only. clearenv(3) keeps glibc's internal environ
         * state consistent — a raw `environ = ...` reassignment segfaults
         * execvp in this whole-program LTO build. */
        if (platform_clear_environment() != 0)
            _exit(PV_CHILD_EXEC_FAIL);
        (void)setenv("PATH", "/usr/local/bin:/usr/bin:/bin", 1);
        (void)setenv("LC_ALL", "C", 1);
        if (env_pairs)
            for (size_t i = 0; env_pairs[i]; i++) {
                const char *eq = strchr(env_pairs[i], '=');
                if (!eq)
                    continue;
                char name[64];
                size_t nl = (size_t)(eq - env_pairs[i]);
                if (nl == 0 || nl >= sizeof(name))
                    continue;
                memcpy(name, env_pairs[i], nl);
                name[nl] = '\0';
                (void)setenv(name, eq + 1, 1);
            }
        /* The parent forwards this pipe (see pr.stderr_buf) into the
         * "failed to launch or arm its sandbox" messages below — without
         * it, a rlimit/Landlock arm failure is a bare exit code with no way
         * to tell a resource-budget miss from a bad grant path. */
        if (limits) {
            struct zcl_result rr = os_sandbox_set_rlimits(limits);
            if (!zcl_result_is_ok(rr)) {
                fprintf(stderr, "rlimits: %s\n", rr.message);
                _exit(PV_CHILD_SANDBOX_FAIL);
            }
        }
        if (!os_sandbox_no_new_privs())
            _exit(PV_CHILD_SANDBOX_FAIL);
        if (landlock) {
            struct zcl_result lr =
                os_sandbox_landlock_restrict(rules, n_rules);
            if (!zcl_result_is_ok(lr)) {
                fprintf(stderr, "landlock: %s\n", lr.message);
                _exit(PV_CHILD_SANDBOX_FAIL);
            }
        }
        struct zcl_result sr = os_sandbox_seccomp_deny(
            g_pv_child_denied, PV_CHILD_DENIED_COUNT,
            false);
        if (!zcl_result_is_ok(sr))
            _exit(PV_CHILD_SECCOMP_FAIL);
        execvp(argv[0], (char *const *)argv);
        _exit(PV_CHILD_EXEC_FAIL);
    }
    /* Same call as the child's, so the group exists no matter which side
     * runs first. EACCES here means the child already exec'd — it set the
     * group itself before doing so, which is the outcome we wanted. */
    (void)setpgid(pid, pid);
    close(out_pipe[1]);
    close(err_pipe[1]);
    /* Nonblocking read ends: the poll loop drains without hanging. */
    (void)fcntl(out_pipe[0], F_SETFL, O_NONBLOCK);
    (void)fcntl(err_pipe[0], F_SETFL, O_NONBLOCK);
    r.launched = true;

    int64_t deadline =
        clock_now_monotonic_ns() + (int64_t)timeout_ms * INT64_C(1000000);
    size_t out_len = 0, err_len = 0;
    int status = 0;
    bool reaped = false;
    int census_tick = 0;
    struct rusage usage;
    memset(&usage, 0, sizeof(usage));
    for (;;) {
        /* PEEK with WNOWAIT: the child stays an unreaped zombie, which keeps
         * its pid reserved and its process group bound to that pid. Only then
         * is kill(-pid) safe — reaping first would let the pid be recycled
         * and the group signal land on somebody else's tree. */
        siginfo_t si;
        memset(&si, 0, sizeof(si));
        int peeked = waitid(P_PID, (id_t)pid, &si,
                            WEXITED | WNOHANG | WNOWAIT);
        if (peeked == 0 && si.si_pid == pid) {
            kill(-pid, SIGKILL);           /* nothing outlives the action */
            (void)wait4(pid, &status, 0, &usage);
            reaped = true;
            break;
        }
        /* Drain whatever the child has written so far (bounded). */
        uint8_t chunk[512];
        ssize_t got;
        got = read(out_pipe[0], chunk, sizeof(chunk));
        if (got > 0) {
            size_t room = sizeof(r.stdout_buf) - 1 - out_len;
            size_t take = (size_t)got < room ? (size_t)got : room;
            if (take) memcpy(r.stdout_buf + out_len, chunk, take);
            out_len += take;
            if (take < (size_t)got) r.stdout_truncated = true;
        }
        got = read(err_pipe[0], chunk, sizeof(chunk));
        if (got > 0) {
            size_t room = sizeof(r.stderr_buf) - 1 - err_len;
            size_t take = (size_t)got < room ? (size_t)got : room;
            if (take) memcpy(r.stderr_buf + err_len, chunk, take);
            err_len += take;
            if (take < (size_t)got) r.stderr_truncated = true;
        }
        /* The action's process budget, enforced where it is meaningful: over
         * the child's own process GROUP, so concurrent work of the same uid
         * is neither counted against this action nor punished by it. */
        if (r.subtree_budget && ++census_tick >= PV_NPROC_CENSUS_TICKS) {
            census_tick = 0;
            uint64_t live = os_sandbox_process_group_census(pid);
            if (live > r.subtree_peak) r.subtree_peak = live;
            if (live > r.subtree_budget) {
                kill(-pid, SIGKILL);
                kill(pid, SIGKILL);
                (void)wait4(pid, &status, 0, &usage);
                reaped = true;
                r.budget_exceeded = true;
                break;
            }
        }
        if (clock_now_monotonic_ns() >= deadline) {
            /* Kill the GROUP, not just the direct child: a descendant that
             * outlived its parent would otherwise survive the deadline. */
            kill(-pid, SIGKILL);
            kill(pid, SIGKILL);
            (void)wait4(pid, &status, 0, &usage);
            reaped = true;
            r.timed_out = true;
            break;
        }
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
        nanosleep(&ts, NULL);
    }
    /* Final drain after the child is gone (pipe holds the last bytes). */
    for (;;) {
        uint8_t chunk[512];
        ssize_t got = read(out_pipe[0], chunk, sizeof(chunk));
        if (got <= 0)
            break;
        if (out_len + 1 < sizeof(r.stdout_buf)) {
            size_t room = sizeof(r.stdout_buf) - 1 - out_len;
            size_t take = (size_t)got < room ? (size_t)got : room;
            memcpy(r.stdout_buf + out_len, chunk, take);
            out_len += take;
            if (take < (size_t)got) r.stdout_truncated = true;
        } else {
            r.stdout_truncated = true;
        }
    }
    for (;;) {
        uint8_t chunk[512];
        ssize_t got = read(err_pipe[0], chunk, sizeof(chunk));
        if (got <= 0)
            break;
        if (err_len + 1 < sizeof(r.stderr_buf)) {
            size_t room = sizeof(r.stderr_buf) - 1 - err_len;
            size_t take = (size_t)got < room ? (size_t)got : room;
            memcpy(r.stderr_buf + err_len, chunk, take);
            err_len += take;
            if (take < (size_t)got) r.stderr_truncated = true;
        } else {
            r.stderr_truncated = true;
        }
    }
    close(out_pipe[0]);
    close(err_pipe[0]);
    r.stdout_buf[out_len] = '\0';
    r.stderr_buf[err_len] = '\0';
    r.stdout_len = out_len;
    r.stderr_len = err_len;
    uint64_t cpu_us = reaped ? pv_rusage_cpu_us(&usage) : 0;
    g_pv_perf.child_cpu_us += cpu_us;
    if (g_pv_cpu_budget_us) {
        g_pv_cpu_used_us += cpu_us;
        if (g_pv_cpu_used_us > g_pv_cpu_budget_us)
            r.timed_out = true;
    }
    (void)reaped;
    if (!r.timed_out) {
        if (WIFEXITED(status)) {
            r.exited = true;
            r.exit_code = WEXITSTATUS(status);
            if (r.exit_code == PV_CHILD_SANDBOX_FAIL ||
                r.exit_code == PV_CHILD_SECCOMP_FAIL)
                r.sandbox_fail = true;
        } else if (WIFSIGNALED(status)) {
            r.term_signal = WTERMSIG(status);
        }
    }
    int64_t perf_elapsed_ns = clock_now_monotonic_ns() - perf_started_ns;
    pv_perf_record(argv ? argv[0] : NULL,
                   perf_elapsed_ns > 0 ? (uint64_t)perf_elapsed_ns / 1000u : 0);
    return r;
}

/* ── store loading ──────────────────────────────────────────────────── */

/* Find the verified release envelope naming package_root: the lowest
 * release id wins when several match (deterministic). False when none. */
static bool pv_load_release(const char *store_dir,
                            const uint8_t package_root[32],
                            struct vcs_package_release *out,
                            uint8_t release_id_out[32])
{
    char dir[4096];
    int n = snprintf(dir, sizeof(dir), "%s/releases", store_dir);
    if (n < 0 || (size_t)n >= sizeof(dir))
        return false;
    DIR *d = opendir(dir);
    if (!d)
        return false;
    bool found = false;
    uint8_t best_id[32];
    memset(best_id, 0xff, 32);
    struct dirent *ent;
    size_t scanned = 0;
    while ((ent = readdir(d)) != NULL && scanned < 4096) {
        uint8_t scratch[32];
        if (!zcl_hex_decode_lower(ent->d_name, scratch, 32))
            continue;
        scanned++;
        char path[4096];
        int pn = snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        if (pn < 0 || (size_t)pn >= sizeof(path))
            continue;
        size_t wire_len = 0;
        uint8_t *wire =
            pv_read_file(path, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
                         &wire_len);
        if (!wire)
            continue;
        struct vcs_package_release rel;
        enum vcs_package_release_error perr =
            vcs_package_release_parse(wire, wire_len, &rel);
        free(wire);
        if (perr != VCS_PACKAGE_RELEASE_OK)
            continue;
        if (memcmp(rel.package_root, package_root, 32) != 0)
            continue;
        if (vcs_package_release_verify(&rel) != VCS_PACKAGE_RELEASE_OK)
            continue;
        uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
        if (vcs_package_release_id(&rel, id) != VCS_PACKAGE_RELEASE_OK)
            continue;
        if (!found || memcmp(id, best_id, 32) < 0) {
            memcpy(best_id, id, 32);
            *out = rel;
            memcpy(release_id_out, id, 32);
            found = true;
        }
    }
    closedir(d);
    return found;
}

/* ── compiler/test invocation plumbing ──────────────────────────────── */

struct pv_compiler {
    const char *id; /* "gcc" / "clang" (attestation tokens) */
    const char *path; /* absolute executable selected by the supervisor */
    char version[VCS_PACKAGE_ATTEST_COMPILER_VERSION_MAX + 1u];
    bool available;
    uint8_t outcome; /* enum vcs_package_attest_outcome (build verdict) */
};

/* Sanitize one bounded printable detail line from captured stderr: the
 * first line containing ": error:" when present, else the first non-empty
 * line; non-printables become '?'. */
static void pv_detail_from_stderr(const char *prefix, const char *stderr_buf,
                                  char *out, size_t out_cap)
{
    /* A modern sandboxed compile reports absolute attempt paths; the
     * materialized `<work>/src/<package-relative>` path alone can pass
     * 200 bytes on a deep checkout, which used to cut the line before
     * its `: error:` marker and mangle the repair coordinates. */
    char line[512];
    line[0] = '\0';
    const char *p = stderr_buf;
    char first[512];
    first[0] = '\0';
    while (p && *p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len >= sizeof(line))
            len = sizeof(line) - 1;
        char cur[512];
        memcpy(cur, p, len);
        cur[len] = '\0';
        if (cur[0] && !first[0])
            snprintf(first, sizeof(first), "%s", cur);
        if (strstr(cur, ": error:") != NULL) {
            snprintf(line, sizeof(line), "%s", cur);
            break;
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    if (!line[0])
        snprintf(line, sizeof(line), "%s", first[0] ? first : "no diagnostics captured");
    /* The isolated materialization path is attempt-specific and can consume
     * the entire bounded diagnostic before the useful line/column/message.
     * Keep the final source-relative `src/...` suffix when the compiler
     * reported one. This is display/repair feedback, never an input path. */
    const char *display = line;
    const char *source_suffix = NULL;
    for (const char *scan = strstr(line, "/src/"); scan;
         scan = strstr(scan + 1u, "/src/"))
        source_suffix = scan;
    if (source_suffix) display = source_suffix + 1u;
    size_t o = snprintf(out, out_cap, "%s: ", prefix);
    for (size_t i = 0; display[i] && o + 1 < out_cap && o < 150; i++) {
        unsigned char c = (unsigned char)display[i];
        out[o++] = (c >= 0x20 && c <= 0x7e) ? (char)c : '?';
    }
    out[o] = '\0';
}

/* Extract the sanitizer's own report line (ASan "SUMMARY:" / UBSan
 * "runtime error:") from captured stderr into the attestation detail, so
 * a findings attestation carries WHAT was found, not just the exit code. */
static void pv_san_detail_from_stderr(const char *prefix,
                                      const char *stderr_buf,
                                      char *out, size_t out_cap)
{
    char line[200];
    line[0] = '\0';
    char first[200];
    first[0] = '\0';
    const char *p = stderr_buf;
    while (p && *p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len >= sizeof(line))
            len = sizeof(line) - 1;
        char cur[200];
        memcpy(cur, p, len);
        cur[len] = '\0';
        if (cur[0] && !first[0])
            snprintf(first, sizeof(first), "%s", cur);
        if (strstr(cur, "SUMMARY:") != NULL ||
            strstr(cur, "runtime error:") != NULL) {
            snprintf(line, sizeof(line), "%s", cur);
            break;
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    if (!line[0])
        snprintf(line, sizeof(line), "%s",
                 first[0] ? first : "sanitizer findings (report truncated)");
    size_t o = snprintf(out, out_cap, "%s: ", prefix);
    for (size_t i = 0; line[i] && o + 1 < out_cap && o < 150; i++) {
        unsigned char c = (unsigned char)line[i];
        out[o++] = (c >= 0x20 && c <= 0x7e) ? (char)c : '?';
    }
    out[o] = '\0';
}

/* Build the argv for one compile: cc -std=c23 -O1 [san] -I... -D...
 * -c <srcfile> -o <obj>. argv storage must outlive the call. */
struct pv_compile_args {
    const char *argv[192];
    char source_prefix_map[4300];
    char inc[8][4200];   /* -I args */
    char dep[PV_EMIT_MAX_DEPS][2100]; /* -I args for locked dependencies */
    char def[64][80];    /* -D args */
    char san[2][64];
};

static size_t pv_compile_argv(struct pv_compile_args *store,
                              const char *cc, bool sanitize,
                              bool warning_fatal,
                              const struct vcs_package_recipe *recipe,
                              const char *src_root,
                              const struct pv_emit_dep *deps, size_t dep_count,
                              const char *src_file, const char *obj_file)
{
    size_t n = 0;
    store->argv[n++] = cc;
    store->argv[n++] = "-std=c23";
    store->argv[n++] = "-O1";
    /* Package artifacts are the Commons' reusable boundary. Make their CPU
     * floor explicit instead of inheriting a worker compiler's configured
     * default: original AMD64/SSE2, with no AVX/AVX2/FMA/BMI requirement. */
    store->argv[n++] = "-march=x86-64";
    store->argv[n++] = "-mtune=generic";
    store->argv[n++] = "-fno-omit-frame-pointer";
    /* The frozen package API surface is Linux POSIX.1-2008. Keep standalone
     * builds on that declared surface rather than accidentally compiling only
     * packages that avoid gmtime_r/flockfile and similar interfaces. */
    store->argv[n++] = "-D_POSIX_C_SOURCE=200809L";
    /* Package source is materialized beneath a fresh work root. Normalize
     * that root before the compiler can embed it through __FILE__ (or
     * equivalent file-name metadata), otherwise identical source built by
     * two independent verifiers produces different object/archive bytes. */
    snprintf(store->source_prefix_map, sizeof(store->source_prefix_map),
             "-ffile-prefix-map=%s=.", src_root);
    store->argv[n++] = store->source_prefix_map;
    if (warning_fatal) {
        store->argv[n++] = "-Wall";
        store->argv[n++] = "-Wextra";
        store->argv[n++] = "-Werror";
    }
    if (sanitize) {
        snprintf(store->san[0], sizeof(store->san[0]),
                 "-fsanitize=address,undefined");
        store->argv[n++] = store->san[0];
        snprintf(store->san[1], sizeof(store->san[1]), "-fno-pie");
        store->argv[n++] = store->san[1];
    }
    for (size_t i = 0; i < recipe->include_dirs.count &&
                        i < sizeof(store->inc) / sizeof(store->inc[0]); i++) {
        snprintf(store->inc[i], sizeof(store->inc[i]), "-I%s/%s", src_root,
                 recipe->include_dirs.items[i]);
        store->argv[n++] = store->inc[i];
    }
    for (size_t i = 0; i < dep_count && i < PV_EMIT_MAX_DEPS; i++) {
        snprintf(store->dep[i], sizeof(store->dep[i]), "-I%s",
                 deps[i].include_dir);
        store->argv[n++] = store->dep[i];
    }
    for (size_t i = 0; i < recipe->defines.count &&
                        i < sizeof(store->def) / sizeof(store->def[0]); i++) {
        snprintf(store->def[i], sizeof(store->def[i]), "-D%s",
                 recipe->defines.items[i]);
        store->argv[n++] = store->def[i];
    }
    store->argv[n++] = "-c";
    store->argv[n++] = src_file;
    store->argv[n++] = "-o";
    store->argv[n++] = obj_file;
    store->argv[n] = NULL;
    return n;
}

/* ── emit-mode helpers (install-build outputs) ──────────────────────── */

/* Absolute paths of every `lib*.a` in each locked dependency's lib/ dir, in
 * REVERSE --dep order: --dep arrives in lock BUILD order (dependencies
 * first), and a static link line wants dependents before their providers. */
struct pv_dep_archives {
    char path[PV_EMIT_MAX_DEPS * 4u][2200];
    size_t count;
};

static int pv_dep_archive_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static bool pv_collect_dep_archives(const struct pv_emit_dep *deps,
                                    size_t dep_count,
                                    struct pv_dep_archives *out)
{
    out->count = 0;
    for (size_t k = dep_count; k > 0; k--) {
        const struct pv_emit_dep *d = &deps[k - 1];
        const size_t first = out->count;
        char lib_dir[2100];
        int n = snprintf(lib_dir, sizeof(lib_dir), "%s/lib", d->install_dir);
        if (n <= 0 || (size_t)n >= sizeof(lib_dir))
            return false;
        DIR *dir = opendir(lib_dir);
        if (!dir)
            return false;
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            size_t nl = strlen(ent->d_name);
            if (nl < 4u || strncmp(ent->d_name, "lib", 3) != 0 ||
                strcmp(ent->d_name + nl - 2u, ".a") != 0)
                continue;
            if (out->count >= sizeof(out->path) / sizeof(out->path[0])) {
                closedir(dir);
                return false;
            }
            int pn = snprintf(out->path[out->count],
                              sizeof(out->path[out->count]), "%s/%s", lib_dir,
                              ent->d_name);
            if (pn > 0 && (size_t)pn < sizeof(out->path[out->count]))
                out->count++;
        }
        closedir(dir);
        qsort(&out->path[first], out->count - first,
              sizeof(out->path[0]), pv_dep_archive_cmp);
    }
    return true;
}

/* A static archive never carries its own providers: zotp.a references zsha1
 * symbols without containing them, so the link line needs the archives of
 * the FULL transitive closure, while the build receipt still commits only
 * the declared direct set (the --dep arguments). Each transitive root's own
 * direct set is read from its installed build-report — a file that reached
 * <installed>/<root>/ only after the installer independently re-hashed every
 * byte against that very receipt. Expansion fails closed on any unreadable
 * or unparseable report: a guessed link is worse than a refused one. The
 * result is dependents-first breadth-first; the link wraps the archive set
 * in --start-group, so residual intra-level order cannot matter. The DAG
 * lock bound (VCS_PACKAGE_LOCK_MAX_NODES == PV_EMIT_MAX_DEPS) caps the
 * closure, so `out` needs no larger bound than the direct set's. */
static bool pv_expand_link_closure(const struct pv_emit_dep *deps,
                                   size_t dep_count,
                                   struct pv_emit_dep *out,
                                   size_t *out_count)
{
    size_t n = 0;
    for (size_t i = 0; i < dep_count && i < PV_EMIT_MAX_DEPS; i++)
        out[n++] = deps[i];
    for (size_t head = 0; head < n; head++) {
        char report[4300];
        int rn = snprintf(report, sizeof(report), "%s/build-report",
                          out[head].install_dir);
        if (rn <= 0 || (size_t)rn >= sizeof(report))
            return false;
        size_t wire_len = 0;
        uint8_t *wire =
            pv_read_file(report, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES, &wire_len);
        if (!wire)
            return false;
        struct vcs_package_build_receipt receipt;
        enum vcs_package_build_error perr =
            vcs_package_build_parse(wire, wire_len, &receipt);
        free(wire);
        if (perr != VCS_PACKAGE_BUILD_OK)
            return false;
        /* The sibling install dirs share this root's parent directory. */
        char parent[2100];
        (void)snprintf(parent, sizeof(parent), "%s", out[head].install_dir);
        char *slash = strrchr(parent, '/');
        if (!slash)
            return false;
        *slash = '\0';
        for (size_t j = 0; j < receipt.dep_count; j++) {
            bool seen = false;
            for (size_t k = 0; k < n; k++)
                if (memcmp(out[k].root, receipt.dep_roots[j], 32) == 0) {
                    seen = true;
                    break;
                }
            if (seen)
                continue;
            if (n >= PV_EMIT_MAX_DEPS)
                return false;
            char hex[65];
            zcl_hex_encode(receipt.dep_roots[j], 32, hex);
            struct pv_emit_dep *d = &out[n];
            memset(d, 0, sizeof(*d));
            memcpy(d->root, receipt.dep_roots[j], 32);
            int dn = snprintf(d->install_dir, sizeof(d->install_dir),
                              "%s/%s", parent, hex);
            if (dn <= 0 || (size_t)dn >= sizeof(d->install_dir))
                return false;
            int in = snprintf(d->include_dir, sizeof(d->include_dir),
                              "%s/include", d->install_dir);
            if (in <= 0 || (size_t)in >= sizeof(d->include_dir))
                return false;
            n++;
        }
    }
    *out_count = n;
    return true;
}

/* SHA3-256 + byte count of one file, streamed in bounded chunks. */
static bool pv_sha3_file(const char *path, uint8_t out[32], uint64_t *bytes)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    uint8_t buf[65536];
    uint64_t total = 0;
    size_t got;
    while ((got = fread(buf, 1, sizeof(buf), f)) > 0) {
        sha3_256_write(&ctx, buf, got);
        total += got;
    }
    bool ok = ferror(f) == 0;
    fclose(f);
    if (!ok)
        return false;
    sha3_256_finalize(&ctx, out);
    *bytes = total;
    return true;
}

static bool pv_copy_file(const char *src, const char *dst, mode_t mode)
{
    FILE *in = fopen(src, "rb");
    if (!in)
        return false;
    char parent[4200];
    (void)snprintf(parent, sizeof(parent), "%s", dst);
    char *slash = strrchr(parent, '/');
    if (slash) {
        *slash = '\0';
        if (!pv_mkdir_p(parent, 0700)) {
            fclose(in);
            return false;
        }
    }
    int fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) {
        fclose(in);
        return false;
    }
    uint8_t buf[65536];
    size_t got;
    bool ok = true;
    while (ok && (got = fread(buf, 1, sizeof(buf), in)) > 0) {
        size_t off = 0;
        while (off < got) {
            ssize_t w = write(fd, buf + off, got - off);
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                ok = false;
                break;
            }
            off += (size_t)w;
        }
    }
    if (ferror(in))
        ok = false;
    fclose(in);
    if (fsync(fd) != 0 || close(fd) != 0)
        ok = false;
    if (!ok)
        unlink(dst);
    return ok;
}

static bool pv_directory_has_exact_files(const char *path,
                                         const char *first,
                                         const char *second)
{
    DIR *dir = opendir(path);
    if (!dir) return false;
    bool saw_first = false, saw_second = second == NULL, ok = true;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        if (strcmp(entry->d_name, first) == 0 && !saw_first)
            saw_first = true;
        else if (second && strcmp(entry->d_name, second) == 0 && !saw_second)
            saw_second = true;
        else {
            ok = false;
            break;
        }
        char full[4200];
        struct stat st;
        int n = snprintf(full, sizeof(full), "%s/%s", path, entry->d_name);
        if (n <= 0 || (size_t)n >= sizeof(full) || lstat(full, &st) != 0 ||
            !S_ISREG(st.st_mode)) {
            ok = false;
            break;
        }
    }
    if (closedir(dir) != 0) ok = false;
    return ok && saw_first && saw_second;
}

static bool pv_directory_is_empty(const char *path)
{
    DIR *dir = opendir(path);
    if (!dir) return false;
    bool empty = true;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) {
            empty = false;
            break;
        }
    if (closedir(dir) != 0) empty = false;
    return empty;
}

/* Install-relative header destination: strip the LONGEST recipe include-dir
 * prefix so `#include <ringbuffer.h>` keeps working after install; a header
 * under no include dir keeps its full package-relative path. */
static void pv_header_install_path(const struct vcs_package_recipe *recipe,
                                   const char *header, char *out,
                                   size_t out_cap)
{
    const char *best = header;
    size_t best_len = 0;
    for (size_t i = 0; i < recipe->include_dirs.count; i++) {
        const char *dir = recipe->include_dirs.items[i];
        size_t dl = strlen(dir);
        if (dl > best_len && strncmp(header, dir, dl) == 0 &&
            header[dl] == '/' && header[dl + 1] != '\0') {
            best = header + dl + 1u;
            best_len = dl;
        }
    }
    (void)snprintf(out, out_cap, "include/%s", best);
}

/* ── dependency plan emission (zcl.dep_plan.v1) ───────────────────────
 *
 * --plan=<path> (emit modes only). BEFORE any real compile, every recipe
 * source TU is preprocessed under the SAME confinement with the EXACT argv
 * the compile would use, plus -E -MD -MF <tmp.d> -o <tmp.i>. The plan
 * records only what the toolchain itself proves:
 *   - the depfile closure: every file the preprocessor actually read, with
 *     SHA3-256 + byte count, classified by the -I root it falls under;
 *   - the preprocessed unit digest (SHA3-256 + bytes; the .i stays in the
 *     temp tree and is never shipped);
 *   - the macro ENVIRONMENT digest (gcc -E -dM). Which macros the TU
 *     actually EXPANDED is not enumerable by gcc14 — not claimed;
 *   - the fixed toolchain identity: exact argv, compiler version, target,
 *     and the v1 toolchain capsule root (vcs/build_action.h, reused).
 * Which public declarations/types a TU uses is "not_claimed": that needs
 * semantic analysis gcc14 cannot provide. Volatile absolute roots inside
 * the recorded argv are rendered as stable tokens (@package, @build,
 * @dep/<root>) so a plan over identical inputs is byte-identical; there
 * are NO wall-clock fields. Any failure aborts the run before the real
 * build (fail closed; the document is written beside the destination and
 * atomically renamed, so a partial plan never exists). */

#define PV_PLAN_SCHEMA "zcl.dep_plan.v1"
#define PV_PLAN_MAX_INPUTS 1024u
#define PV_PLAN_DEPFILE_CAP (1024u * 1024u)

struct pv_plan_input {
    char display[4300]; /* package-/dep-relative, or absolute (system) */
    char class[24];
    uint8_t dep_root[32]; /* dependency_header only */
    bool has_dep_root;
    uint8_t sha3[32];
    uint64_t bytes;
};

struct pv_plan_ctx {
    const struct vcs_package_recipe *recipe;
    const char *src_root;
    const char *build_root;
    const struct pv_emit_dep *deps;
    size_t dep_count;
    const struct os_sandbox_path_rule *rules;
    size_t n_rules;
    bool landlock;
    const char *const *env;
    const struct os_sandbox_rlimits *limits;
    bool warning_fatal;
    char error[240];
};

static bool pv_plan_error(struct pv_plan_ctx *ctx, const char *what)
{
    (void)snprintf(ctx->error, sizeof(ctx->error), "%s", what);
    return false;
}

static bool pv_strlist_has(const struct vcs_package_recipe_strings *list,
                           const char *s)
{
    for (size_t i = 0; i < list->count; i++)
        if (strcmp(list->items[i], s) == 0)
            return true;
    return false;
}

/* Classify one depfile path by the -I root it falls under, hash it, and
 * append it (deduped on class + display + dep_root). */
static bool pv_plan_add_input(struct pv_plan_ctx *ctx,
                              struct pv_plan_input *inputs, size_t *count,
                              const char *path)
{
    char display[4300];
    const char *class = "system_header";
    const uint8_t *dep_root = NULL;
    size_t rl = strlen(ctx->src_root);
    if (strncmp(path, ctx->src_root, rl) == 0 && path[rl] == '/') {
        const char *rel = path + rl + 1;
        if (pv_strlist_has(&ctx->recipe->sources, rel))
            class = "package_source";
        else if (pv_strlist_has(&ctx->recipe->public_headers, rel))
            class = "package_public_header";
        else
            class = "package_internal";
        if (snprintf(display, sizeof(display), "%s", rel) >=
                (int)sizeof(display))
            return pv_plan_error(ctx, "depfile path too long");
    } else {
        bool matched = false;
        for (size_t i = 0; i < ctx->dep_count && !matched; i++) {
            size_t dl = strlen(ctx->deps[i].include_dir);
            if (strncmp(path, ctx->deps[i].include_dir, dl) != 0 ||
                path[dl] != '/')
                continue;
            class = "dependency_header";
            dep_root = ctx->deps[i].root;
            if (snprintf(display, sizeof(display), "%s", path + dl + 1) >=
                    (int)sizeof(display))
                return pv_plan_error(ctx, "depfile path too long");
            matched = true;
        }
        if (!matched &&
            snprintf(display, sizeof(display), "%s", path) >=
                (int)sizeof(display))
            return pv_plan_error(ctx, "depfile path too long");
    }
    for (size_t i = 0; i < *count; i++) {
        if (strcmp(inputs[i].display, display) == 0 &&
            strcmp(inputs[i].class, class) == 0 &&
            (!dep_root ||
             (inputs[i].has_dep_root &&
              memcmp(inputs[i].dep_root, dep_root, 32) == 0)))
            return true;
    }
    if (*count >= PV_PLAN_MAX_INPUTS)
        return pv_plan_error(ctx, "dependency closure over the plan bound");
    struct pv_plan_input *in = &inputs[*count];
    memset(in, 0, sizeof(*in));
    (void)snprintf(in->display, sizeof(in->display), "%s", display);
    (void)snprintf(in->class, sizeof(in->class), "%s", class);
    if (dep_root) {
        memcpy(in->dep_root, dep_root, 32);
        in->has_dep_root = true;
    }
    if (!pv_sha3_file(path, in->sha3, &in->bytes)) {
        (void)snprintf(ctx->error, sizeof(ctx->error),
                       "cannot hash depfile entry %.160s", path);
        return false;
    }
    (*count)++;
    return true;
}

/* Parse a GNU make depfile: the rule target (to the first unescaped ':')
 * is skipped, backslash-newline is a line continuation, backslash escapes
 * the following byte, and whitespace separates the path tokens. */
static bool pv_plan_depfile_inputs(struct pv_plan_ctx *ctx,
                                   const uint8_t *buf, size_t len,
                                   struct pv_plan_input *inputs,
                                   size_t *count)
{
    size_t pos = 0;
    bool colon = false;
    while (pos < len && !colon) {
        if (buf[pos] == '\\' && pos + 1 < len) {
            pos += 2;
            continue;
        }
        colon = buf[pos] == ':';
        pos++;
    }
    if (!colon)
        return pv_plan_error(ctx, "depfile carries no rule target");
    while (pos < len) {
        while (pos < len && (buf[pos] == ' ' || buf[pos] == '\t' ||
                             buf[pos] == '\n' || buf[pos] == '\r'))
            pos++;
        if (pos >= len)
            break;
        char tok[4300];
        size_t tl = 0;
        while (pos < len && buf[pos] != ' ' && buf[pos] != '\t' &&
               buf[pos] != '\n' && buf[pos] != '\r') {
            if (buf[pos] == '\\') {
                if (pos + 1 < len && buf[pos + 1] == '\n') {
                    pos += 2;
                    break; /* a continuation ends this token */
                }
                if (pos + 1 >= len)
                    break;
                if (tl + 1 >= sizeof(tok))
                    return pv_plan_error(ctx, "depfile token too long");
                tok[tl++] = (char)buf[pos + 1];
                pos += 2;
                continue;
            }
            if (tl + 1 >= sizeof(tok))
                return pv_plan_error(ctx, "depfile token too long");
            tok[tl++] = (char)buf[pos++];
        }
        tok[tl] = '\0';
        if (tl && !pv_plan_add_input(ctx, inputs, count, tok))
            return false;
    }
    return true;
}

static int pv_plan_input_cmp(const void *a, const void *b)
{
    const struct pv_plan_input *ia = a;
    const struct pv_plan_input *ib = b;
    int c = strcmp(ia->display, ib->display);
    if (c != 0)
        return c;
    c = strcmp(ia->class, ib->class);
    if (c != 0)
        return c;
    return memcmp(ia->dep_root, ib->dep_root, 32);
}

/* The preprocess probe argv: the exact compile flag vector with the
 * "-c src -o obj" tail replaced by "-E [-dM | -MD -MF <d>] src -o out". */
static bool pv_plan_probe_argv(const char *out[], size_t cap,
                               const struct pv_compile_args *base,
                               bool macros, const char *mf_path,
                               const char *src_file, const char *out_file)
{
    size_t n = 0, i = 0;
    while (base->argv[i] && strcmp(base->argv[i], "-c") != 0) {
        if (n + 8u >= cap)
            return false;
        out[n++] = base->argv[i++];
    }
    if (!base->argv[i])
        return false; /* the compile vector always carries -c */
    out[n++] = "-E";
    if (macros) {
        out[n++] = "-dM";
    } else {
        out[n++] = "-MD";
        out[n++] = "-MF";
        out[n++] = mf_path;
    }
    out[n++] = src_file;
    out[n++] = "-o";
    out[n++] = out_file;
    out[n] = NULL;
    return true;
}

/* Render one argv element for the plan: the volatile absolute roots are
 * replaced by stable tokens (@package, @build, @dep/<root hex>). With the
 * plan-level bindings this is a lossless encoding of the exact argv. */
static bool pv_plan_render_arg(const struct pv_plan_ctx *ctx,
                               const char *arg, char *out, size_t cap)
{
    struct {
        const char *root;
        char token[88];
    } maps[2u + PV_EMIT_MAX_DEPS];
    size_t nmaps = 0;
    maps[nmaps].root = ctx->src_root;
    (void)snprintf(maps[nmaps].token, sizeof(maps[nmaps].token),
                   "@package");
    nmaps++;
    maps[nmaps].root = ctx->build_root;
    (void)snprintf(maps[nmaps].token, sizeof(maps[nmaps].token), "@build");
    nmaps++;
    for (size_t i = 0; i < ctx->dep_count; i++) {
        char hex[65];
        zcl_hex_encode(ctx->deps[i].root, 32, hex);
        maps[nmaps].root = ctx->deps[i].install_dir;
        (void)snprintf(maps[nmaps].token, sizeof(maps[nmaps].token),
                       "@dep/%s", hex);
        nmaps++;
    }
    const char *hit = NULL;
    size_t mi = 0;
    for (size_t i = 0; i < nmaps; i++) {
        const char *p = strstr(arg, maps[i].root);
        if (p && (!hit || p < hit)) {
            hit = p;
            mi = i;
        }
    }
    if (!hit)
        return snprintf(out, cap, "%s", arg) < (int)cap;
    int n = snprintf(out, cap, "%.*s%s%s", (int)(hit - arg), arg,
                     maps[mi].token, hit + strlen(maps[mi].root));
    return n > 0 && (size_t)n < cap;
}

/* Run the preprocess probes for every recipe source TU and write the plan
 * document to plan_path. When preproc_out is non-NULL it receives each
 * TU's preprocessed-unit SHA3-256 so a --fast-cache in the same run does
 * not preprocess twice. False with ctx->error set on any failure — the
 * caller then fails the whole run closed before any real compile. */
static bool pv_emit_dep_plan(const char *plan_path, const char *package_name,
                             const uint8_t package_root[32],
                             const uint8_t recipe_root[32],
                             const uint8_t lock_root[32],
                             const char *profile, const char *cc_id,
                             const char *cc_path, const char *cc_version,
                             struct pv_plan_ctx *ctx,
                             uint8_t preproc_out[][32])
{
    struct vcs_toolchain_capsule_v1 capsule;
    uint8_t capsule_root[32];
    if (!vcs_toolchain_capsule_v1_capture_gcc(&capsule) ||
        !vcs_toolchain_capsule_v1_root(&capsule, capsule_root))
        return pv_plan_error(ctx, "toolchain capsule capture failed");

    struct pv_plan_input *inputs =
        zcl_malloc(sizeof(struct pv_plan_input) * PV_PLAN_MAX_INPUTS,
                   "pv_plan.inputs");
    if (!inputs)
        return pv_plan_error(ctx, "plan input table alloc failed");

    struct json_value root;
    json_init(&root);
    json_set_object(&root);
    char hex[65];
    bool ok = json_push_kv_str(&root, "schema", PV_PLAN_SCHEMA) &&
              json_push_kv_str(&root, "package_name", package_name);
    zcl_hex_encode(package_root, 32, hex);
    ok = ok && json_push_kv_str(&root, "package_root", hex);
    zcl_hex_encode(recipe_root, 32, hex);
    ok = ok && json_push_kv_str(&root, "recipe_root", hex);
    zcl_hex_encode(lock_root, 32, hex);
    ok = ok && json_push_kv_str(&root, "lock_root", hex) &&
         json_push_kv_str(&root, "profile", profile) &&
         json_push_kv_str(&root, "argv_path_encoding",
                          "@package=package source root (see package_root); "
                          "@build=ephemeral work dir; @dep/<root>=dependency "
                          "install dir; substitute to reconstruct the exact "
                          "byte argv");
    {
        struct json_value jdeps;
        json_init(&jdeps);
        json_set_array(&jdeps);
        for (size_t i = 0; ok && i < ctx->dep_count; i++) {
            struct json_value d;
            json_init(&d);
            json_set_object(&d);
            zcl_hex_encode(ctx->deps[i].root, 32, hex);
            ok = json_push_kv_str(&d, "root", hex) &&
                 json_push_back(&jdeps, &d);
            json_free(&d);
        }
        ok = ok && json_push_kv(&root, "deps", &jdeps);
        json_free(&jdeps);
    }
    {
        struct json_value tc;
        json_init(&tc);
        json_set_object(&tc);
        zcl_hex_encode(capsule_root, 32, hex);
        /* march/mtune mirror the fixed flags pv_compile_argv emits; the
         * argv array below carries them verbatim. */
        ok = ok && json_push_kv_str(&tc, "compiler_id", cc_id) &&
             json_push_kv_str(&tc, "compiler_version", cc_version) &&
             json_push_kv_str(&tc, "march", "x86-64") &&
             json_push_kv_str(&tc, "mtune", "generic") &&
             json_push_kv_str(&tc, "target", capsule.target) &&
             json_push_kv_str(&tc, "capsule_root", hex) &&
             json_push_kv(&root, "toolchain", &tc);
        json_free(&tc);
    }
    struct json_value tus;
    json_init(&tus);
    json_set_array(&tus);
    for (size_t si = 0; ok && si < ctx->recipe->sources.count; si++) {
        const char *rel = ctx->recipe->sources.items[si];
        char src_file[4300], obj_file[4400], dpath[4400], ipath[4400],
             mpath[4400];
        if (snprintf(src_file, sizeof(src_file), "%s/%s", ctx->src_root,
                     rel) >= (int)sizeof(src_file) ||
            snprintf(obj_file, sizeof(obj_file), "%s/plan_%zu.o",
                     ctx->build_root, si) >= (int)sizeof(obj_file) ||
            snprintf(dpath, sizeof(dpath), "%s/plan_%zu.d",
                     ctx->build_root, si) >= (int)sizeof(dpath) ||
            snprintf(ipath, sizeof(ipath), "%s/plan_%zu.i",
                     ctx->build_root, si) >= (int)sizeof(ipath) ||
            snprintf(mpath, sizeof(mpath), "%s/plan_%zu.macros",
                     ctx->build_root, si) >= (int)sizeof(mpath)) {
            (void)pv_plan_error(ctx, "plan path overflow");
            ok = false;
            break;
        }
        struct pv_compile_args store;
        memset(&store, 0, sizeof(store));
        pv_compile_argv(&store, cc_path, false, ctx->warning_fatal,
                        ctx->recipe, ctx->src_root, ctx->deps,
                        ctx->dep_count, src_file, obj_file);
        const char *pargv[224];
        if (!pv_plan_probe_argv(pargv, sizeof(pargv) / sizeof(pargv[0]),
                                &store, false, dpath, src_file, ipath)) {
            (void)pv_plan_error(ctx, "preprocess argv construction failed");
            ok = false;
            break;
        }
        struct pv_run pr = pv_run_child(pargv, ctx->build_root, ctx->limits,
                                        ctx->landlock, ctx->rules,
                                        ctx->n_rules, ctx->env,
                                        PV_COMPILE_TIMEOUT_MS);
        if (!pr.launched || pr.sandbox_fail) {
            (void)snprintf(ctx->error, sizeof(ctx->error),
                           "preprocess child failed to launch or arm its "
                           "sandbox (%.80s)", pr.stderr_buf);
            ok = false;
            break;
        }
        if (pr.timed_out || !pr.exited || pr.exit_code != 0) {
            char detail[200];
            pv_detail_from_stderr("preprocess", pr.stderr_buf, detail,
                                  sizeof(detail));
            (void)snprintf(ctx->error, sizeof(ctx->error), "%s: %.150s",
                           pr.timed_out ? "preprocess timed out"
                                        : "preprocess failed",
                           detail);
            ok = false;
            break;
        }
        size_t dlen = 0;
        uint8_t *dbuf = pv_read_file(dpath, PV_PLAN_DEPFILE_CAP, &dlen);
        if (!dbuf) {
            (void)pv_plan_error(ctx, "cannot read the emitted depfile");
            ok = false;
            break;
        }
        size_t count = 0;
        bool parsed = pv_plan_depfile_inputs(ctx, dbuf, dlen, inputs,
                                             &count);
        free(dbuf);
        if (!parsed) {
            ok = false;
            break;
        }
        qsort(inputs, count, sizeof(inputs[0]), pv_plan_input_cmp);
        uint8_t ihash[32];
        uint64_t ibytes = 0;
        if (!pv_sha3_file(ipath, ihash, &ibytes)) {
            (void)pv_plan_error(ctx, "cannot hash the preprocessed unit");
            ok = false;
            break;
        }
        if (preproc_out)
            memcpy(preproc_out[si], ihash, 32);
        /* The macro ENVIRONMENT (gcc -E -dM on the same argv). A dump
         * failure degrades this one section to not_claimed with the
         * reason; it never guesses. */
        uint8_t mhash[32];
        uint64_t mbytes = 0;
        bool macro_hashed = false;
        char macro_note[200];
        macro_note[0] = '\0';
        const char *margv[224];
        if (pv_plan_probe_argv(margv, sizeof(margv) / sizeof(margv[0]),
                               &store, true, NULL, src_file, mpath)) {
            struct pv_run mr = pv_run_child(
                margv, ctx->build_root, ctx->limits, ctx->landlock,
                ctx->rules, ctx->n_rules, ctx->env, PV_COMPILE_TIMEOUT_MS);
            if (mr.launched && !mr.sandbox_fail && !mr.timed_out &&
                mr.exited && mr.exit_code == 0 &&
                pv_sha3_file(mpath, mhash, &mbytes)) {
                macro_hashed = true;
            } else {
                pv_detail_from_stderr("macro dump", mr.stderr_buf,
                                      macro_note, sizeof(macro_note));
            }
        } else {
            (void)snprintf(macro_note, sizeof(macro_note),
                           "macro probe argv construction failed");
        }

        struct json_value tu;
        json_init(&tu);
        json_set_object(&tu);
        ok = json_push_kv_str(&tu, "source", rel);
        {
            struct json_value jargv;
            json_init(&jargv);
            json_set_array(&jargv);
            for (size_t a = 0; ok && store.argv[a]; a++) {
                char rendered[4400];
                if (!pv_plan_render_arg(ctx, store.argv[a], rendered,
                                        sizeof(rendered))) {
                    (void)pv_plan_error(ctx, "argv render overflow");
                    ok = false;
                    break;
                }
                struct json_value el;
                json_init(&el);
                json_set_str(&el, rendered);
                ok = json_push_back(&jargv, &el);
                json_free(&el);
            }
            ok = ok && json_push_kv(&tu, "argv", &jargv);
            json_free(&jargv);
        }
        {
            struct json_value jin;
            json_init(&jin);
            json_set_array(&jin);
            for (size_t k = 0; ok && k < count; k++) {
                struct json_value f;
                json_init(&f);
                json_set_object(&f);
                ok = json_push_kv_str(&f, "path", inputs[k].display) &&
                     json_push_kv_str(&f, "class", inputs[k].class);
                if (ok && inputs[k].has_dep_root) {
                    zcl_hex_encode(inputs[k].dep_root, 32, hex);
                    ok = json_push_kv_str(&f, "dep_root", hex);
                }
                char fhex[65];
                zcl_hex_encode(inputs[k].sha3, 32, fhex);
                ok = ok && json_push_kv_str(&f, "sha3", fhex) &&
                     json_push_kv_int(&f, "bytes",
                                      (int64_t)inputs[k].bytes) &&
                     json_push_back(&jin, &f);
                json_free(&f);
            }
            ok = ok && json_push_kv(&tu, "inputs", &jin);
            json_free(&jin);
        }
        {
            struct json_value pp;
            json_init(&pp);
            json_set_object(&pp);
            char phex[65];
            zcl_hex_encode(ihash, 32, phex);
            ok = ok && json_push_kv_str(&pp, "sha3", phex) &&
                 json_push_kv_int(&pp, "bytes", (int64_t)ibytes) &&
                 json_push_kv(&tu, "preprocessed", &pp);
            json_free(&pp);
        }
        {
            struct json_value mac;
            json_init(&mac);
            json_set_object(&mac);
            if (macro_hashed) {
                char mhex[65];
                zcl_hex_encode(mhash, 32, mhex);
                ok = json_push_kv_str(&mac, "status", "environment_only") &&
                     json_push_kv_str(&mac, "defined_macro_sha3", mhex) &&
                     json_push_kv_str(&mac, "note",
                                      "expansion usage not enumerable by "
                                      "gcc14; not claimed");
            } else {
                ok = json_push_kv_str(&mac, "status", "not_claimed") &&
                     json_push_kv_str(&mac, "note",
                                      macro_note[0] ? macro_note
                                                    : "macro dump unavailable");
            }
            ok = ok && json_push_kv(&tu, "macros", &mac);
            json_free(&mac);
        }
        {
            struct json_value decl;
            json_init(&decl);
            json_set_object(&decl);
            ok = ok && json_push_kv_str(&decl, "status", "not_claimed") &&
                 json_push_kv_str(&decl, "note",
                                  "requires semantic analysis; gcc14 "
                                  "cannot prove") &&
                 json_push_kv(&tu, "declarations", &decl);
            json_free(&decl);
        }
        ok = ok && json_push_back(&tus, &tu);
        json_free(&tu);
    }
    ok = ok && json_push_kv(&root, "translation_units", &tus);
    json_free(&tus);

    if (!ok) {
        if (!ctx->error[0])
            (void)pv_plan_error(ctx, "plan JSON assembly failed");
        json_free(&root);
        free(inputs);
        return false;
    }
    size_t need = json_write(&root, NULL, 0);
    char *text = zcl_malloc(need + 2u, "pv_plan.out");
    if (!text) {
        json_free(&root);
        free(inputs);
        return pv_plan_error(ctx, "plan output alloc failed");
    }
    size_t written = json_write(&root, text, need + 1u);
    json_free(&root);
    free(inputs);
    if (written > need) {
        free(text);
        return pv_plan_error(ctx, "plan output overflow");
    }
    text[written] = '\n';
    bool wrote = pv_atomic_write(plan_path, (const uint8_t *)text,
                                 written + 1u);
    free(text);
    if (!wrote) {
        (void)snprintf(ctx->error, sizeof(ctx->error),
                       "cannot write the plan file %.160s", plan_path);
        return false;
    }
    return true;
}

/* ── fast object cache (zcl.fastobj.v1) ───────────────────────────────
 *
 * --fast-cache=<dir> (candidate emit mode only). A LOCAL, QUARANTINED
 * per-translation-unit object cache: before the gcc plain compile of each
 * recipe TU (sources and test sources), the cache key is derived from facts
 * the toolchain proves — SHA3-256 over the domain "zcl.fastobj.v1" (with
 * its NUL), the v1 toolchain capsule root, the target and profile strings,
 * the EXACT compile argv (volatile roots normalized with the plan's
 * @package/@build/@dep/<root> encoding), and the SHA3-256 of the
 * preprocessed unit (the -E probe is shared with --plan when both run —
 * no TU is preprocessed twice).
 *
 *   <dir>/objects/<2 hex>/<62 hex>.o      the cached object (0444)
 *   <dir>/objects/<2 hex>/<62 hex>.json   zcl.fastobj.sidecar.v1
 *
 * HIT: the sidecar's object_sha3 is verified against the cached bytes, the
 * object is materialized at the compile's obj path (hardlink, else copy —
 * the publish_exact discipline), the materialized bytes are re-verified,
 * and the gcc spawn is SKIPPED. The build receipt still re-hashes every
 * output from the real bytes, so a hit cannot change what is committed.
 * MISS: the compile runs normally, then the object + sidecar are stored
 * atomically (temp + fsync + rename). An existing entry under the same key
 * is byte-verified, never overwritten; a mismatch, a torn entry (object
 * without sidecar or vice versa), or a sidecar/object hash mismatch is
 * CACHE CORRUPTION and fails the whole run closed with a clear error.
 *
 * The cache directory is written ONLY by this parent process from bytes the
 * confined compiler produced; the confined children never see it (no
 * Landlock grant), so package code cannot poison it. Cached objects are
 * local candidate evidence (admission=local_candidate): only the secure
 * admission path may promote anything. The signed/canonical receipt wire
 * format is untouched; the counters go to the run's stdout summary. */

#define PV_FASTOBJ_SIDECAR_CAP (256u * 1024u)
#define PV_COMPILE_ARGV_MAX 192u

static uint64_t g_pv_fast_hits;
static uint64_t g_pv_fast_misses;
static uint64_t g_pv_fast_reused_bytes;

/* Run the preprocess probe (-E -MD) for one TU with the exact compile flag
 * vector in `store` and hash the preprocessed unit. False with err set. */
static bool pv_fast_preproc_sha3(struct pv_plan_ctx *ctx,
                                 const struct pv_compile_args *store,
                                 size_t si, const char *src_file,
                                 uint8_t out[32], char *err, size_t err_cap)
{
    char dpath[4400], ipath[4400];
    if (snprintf(dpath, sizeof(dpath), "%s/fast_%zu.d", ctx->build_root,
                 si) >= (int)sizeof(dpath) ||
        snprintf(ipath, sizeof(ipath), "%s/fast_%zu.i", ctx->build_root,
                 si) >= (int)sizeof(ipath)) {
        (void)snprintf(err, err_cap, "fast-cache probe path overflow");
        return false;
    }
    const char *pargv[224];
    if (!pv_plan_probe_argv(pargv, sizeof(pargv) / sizeof(pargv[0]) - 1u,
                            store, false, dpath, src_file, ipath)) {
        (void)snprintf(err, err_cap, "fast-cache probe argv failed");
        return false;
    }
    /* Digest the unit WITHOUT line markers (-P): gcc does not rewrite the
     * marker paths for -ffile-prefix-map, so with markers the digest would
     * depend on the absolute source path, and on pure line shifts from
     * comment edits — neither of which the object (built without -g) can
     * record. __FILE__/__LINE__ EXPANSIONS remain in the -P output, so a
     * semantic change still misses. */
    size_t pn = 0, pe = 0;
    while (pargv[pn])
        pn++;
    while (pe < pn && strcmp(pargv[pe], "-E") != 0)
        pe++;
    if (pe == pn) {
        (void)snprintf(err, err_cap, "fast-cache probe argv has no -E");
        return false;
    }
    for (size_t k = pn; k > pe; k--)
        pargv[k + 1] = pargv[k];
    pargv[pe + 1] = "-P";
    struct pv_run pr = pv_run_child(pargv, ctx->build_root, ctx->limits,
                                    ctx->landlock, ctx->rules, ctx->n_rules,
                                    ctx->env, PV_COMPILE_TIMEOUT_MS);
    if (!pr.launched || pr.sandbox_fail || pr.timed_out || !pr.exited ||
        pr.exit_code != 0) {
        char detail[200];
        pv_detail_from_stderr("fast-cache probe", pr.stderr_buf, detail,
                              sizeof(detail));
        (void)snprintf(err, err_cap, "%.150s", detail);
        return false;
    }
    uint64_t ibytes = 0;
    if (!pv_sha3_file(ipath, out, &ibytes)) {
        (void)snprintf(err, err_cap, "cannot hash the preprocessed unit");
        return false;
    }
    return true;
}

/* The cache key: domain || capsule_root || target || profile || the exact
 * (root-normalized) compile argv || preprocessed-unit SHA3-256. The
 * derivation itself lives in lib/vcs (vcs/fastobj.h) so the carrier that
 * moves cache entries between nodes proves entry placement with the SAME
 * key — one authority, no second source of truth. */
static bool pv_fastobj_key(struct pv_plan_ctx *ctx, const char *profile,
                           const char *target, const uint8_t capsule_root[32],
                           const struct pv_compile_args *store,
                           const uint8_t preproc_sha3[32], uint8_t out[32])
{
    /* Rendered argv, NULL-terminated for vcs_fastobj_key. */
    const char *rendered[PV_COMPILE_ARGV_MAX + 1u];
    size_t count = 0;
    for (size_t i = 0; store->argv[i]; i++) {
        if (count >= PV_COMPILE_ARGV_MAX)
            return false;
        char *one = zcl_malloc(4400, "pv_fastobj.render");
        if (!one)
            return false;
        if (!pv_plan_render_arg(ctx, store->argv[i], one, 4400)) {
            free(one);
            return false;
        }
        rendered[count++] = one;
    }
    rendered[count] = NULL;
    bool ok = vcs_fastobj_key(capsule_root, target, profile, rendered,
                              preproc_sha3, out);
    for (size_t i = 0; i < count; i++)
        free((void *)rendered[i]);
    return ok;
}

static bool pv_fastobj_paths(const char *cache_dir, const uint8_t key[32],
                             char obj_path[], size_t obj_cap,
                             char side_path[], size_t side_cap)
{
    char hex[65];
    zcl_hex_encode(key, 32, hex);
    int on = snprintf(obj_path, obj_cap, "%s/objects/%.2s/%s.o", cache_dir,
                      hex, hex + 2);
    int sn = snprintf(side_path, side_cap, "%s/objects/%.2s/%s.json",
                      cache_dir, hex, hex + 2);
    return on > 0 && (size_t)on < obj_cap && sn > 0 &&
           (size_t)sn < side_cap;
}

/* The sidecar document (zcl.fastobj.sidecar.v1). Heap; caller frees. */
static char *pv_fastobj_sidecar(struct pv_plan_ctx *ctx, const char *profile,
                                const char *target,
                                const uint8_t capsule_root[32],
                                const struct pv_compile_args *args,
                                const uint8_t preproc[32], const char *rel,
                                const uint8_t package_root[32],
                                const uint8_t recipe_root[32],
                                const uint8_t lock_root[32],
                                const uint8_t object_sha3[32],
                                uint64_t object_bytes, size_t *out_len)
{
    struct json_value root;
    json_init(&root);
    json_set_object(&root);
    char hex[65];
    bool ok = json_push_kv_str(&root, "schema", VCS_FASTOBJ_SIDECAR_SCHEMA);
    {
        struct json_value kc;
        json_init(&kc);
        json_set_object(&kc);
        zcl_hex_encode(capsule_root, 32, hex);
        ok = ok && json_push_kv_str(&kc, "capsule_root", hex) &&
             json_push_kv_str(&kc, "target", target) &&
             json_push_kv_str(&kc, "profile", profile);
        {
            struct json_value jargv;
            json_init(&jargv);
            json_set_array(&jargv);
            for (size_t a = 0; ok && args->argv[a]; a++) {
                char rendered[4400];
                if (!pv_plan_render_arg(ctx, args->argv[a], rendered,
                                        sizeof(rendered))) {
                    ok = false;
                    break;
                }
                struct json_value el;
                json_init(&el);
                json_set_str(&el, rendered);
                ok = json_push_back(&jargv, &el);
                json_free(&el);
            }
            ok = ok && json_push_kv(&kc, "argv", &jargv);
            json_free(&jargv);
        }
        zcl_hex_encode(preproc, 32, hex);
        ok = ok && json_push_kv_str(&kc, "preprocessed_sha3", hex);
        {
            struct json_value jdeps;
            json_init(&jdeps);
            json_set_array(&jdeps);
            for (size_t i = 0; ok && i < ctx->dep_count; i++) {
                struct json_value el;
                json_init(&el);
                zcl_hex_encode(ctx->deps[i].root, 32, hex);
                json_set_str(&el, hex);
                ok = json_push_back(&jdeps, &el);
                json_free(&el);
            }
            ok = ok && json_push_kv(&kc, "dep_roots", &jdeps);
            json_free(&jdeps);
        }
        ok = ok && json_push_kv(&root, "key_components", &kc);
        json_free(&kc);
    }
    zcl_hex_encode(package_root, 32, hex);
    ok = ok && json_push_kv_str(&root, "package_root", hex);
    zcl_hex_encode(recipe_root, 32, hex);
    ok = ok && json_push_kv_str(&root, "recipe_root", hex);
    zcl_hex_encode(lock_root, 32, hex);
    ok = ok && json_push_kv_str(&root, "lock_root", hex) &&
         json_push_kv_str(&root, "source", rel);
    zcl_hex_encode(object_sha3, 32, hex);
    ok = ok && json_push_kv_str(&root, "object_sha3", hex) &&
         json_push_kv_int(&root, "object_bytes", (int64_t)object_bytes) &&
         json_push_kv_str(&root, "admission", "local_candidate") &&
         json_push_kv_str(&root, "note",
                          "quarantined local candidate; not promoted "
                          "evidence");
    if (!ok) {
        json_free(&root);
        return NULL;
    }
    size_t need = json_write(&root, NULL, 0);
    char *text = zcl_malloc(need + 2u, "pv_fastobj.sidecar");
    if (!text) {
        json_free(&root);
        return NULL;
    }
    size_t written = json_write(&root, text, need + 1u);
    json_free(&root);
    if (written > need) {
        free(text);
        return NULL;
    }
    text[written] = '\n';
    *out_len = written + 1u;
    return text;
}

/* Look one key up. Returns 1 = hit (object materialized at obj_file and
 * verified), 0 = miss, -1 = fatal (torn/corrupt entry or I/O; err set —
 * the caller fails the run closed). */
static int pv_fast_cache_lookup(const char *cache_dir, const uint8_t key[32],
                                const char *obj_file, char *err,
                                size_t err_cap)
{
    char obj_path[4400], side_path[4400];
    if (!pv_fastobj_paths(cache_dir, key, obj_path, sizeof(obj_path),
                          side_path, sizeof(side_path))) {
        (void)snprintf(err, err_cap, "fast-cache path overflow");
        return -1;
    }
    struct stat st;
    bool has_obj = stat(obj_path, &st) == 0;
    bool has_side = stat(side_path, &st) == 0;
    if (!has_obj && !has_side) {
        g_pv_fast_misses++;
        return 0;
    }
    if (has_obj != has_side) {
        (void)snprintf(err, err_cap,
                       "fast cache torn entry (%s): %.200s",
                       has_obj ? "object without sidecar"
                               : "sidecar without object",
                       has_obj ? obj_path : side_path);
        return -1;
    }
    size_t slen = 0;
    uint8_t *sbuf = pv_read_file(side_path, PV_FASTOBJ_SIDECAR_CAP, &slen);
    if (!sbuf) {
        (void)snprintf(err, err_cap, "fast cache sidecar unreadable: %.200s",
                       side_path);
        return -1;
    }
    struct json_value doc;
    json_init(&doc);
    bool parsed = json_read(&doc, (const char *)sbuf, slen);
    free(sbuf);
    const char *osha =
        parsed ? json_get_str(json_get(&doc, "object_sha3")) : NULL;
    uint8_t expect[32];
    bool expect_ok = osha && strlen(osha) == 64 &&
                     zcl_hex_decode(osha, expect, 32);
    json_free(&doc);
    if (!expect_ok) {
        (void)snprintf(err, err_cap, "fast cache sidecar invalid: %.200s",
                       side_path);
        return -1;
    }
    uint8_t actual[32];
    uint64_t bytes = 0;
    if (!pv_sha3_file(obj_path, actual, &bytes) ||
        memcmp(actual, expect, 32) != 0) {
        (void)snprintf(err, err_cap,
                       "fast cache CORRUPTION: cached object %.200s does "
                       "not match its sidecar", obj_path);
        return -1;
    }
    /* publish_exact discipline: hardlink, else copy; then re-verify the
     * materialized bytes against the sidecar commitment. */
    if (link(obj_path, obj_file) != 0 &&
        !pv_copy_file(obj_path, obj_file, 0644)) {
        (void)snprintf(err, err_cap,
                       "cannot materialize cached object %.200s", obj_path);
        return -1;
    }
    uint8_t mv[32];
    uint64_t mbytes = 0;
    if (!pv_sha3_file(obj_file, mv, &mbytes) ||
        memcmp(mv, expect, 32) != 0) {
        (void)snprintf(err, err_cap,
                       "fast cache materialization failed verification: "
                       "%.200s", obj_file);
        return -1;
    }
    g_pv_fast_hits++;
    g_pv_fast_reused_bytes += bytes;
    return 1;
}

/* Store a freshly compiled object + sidecar under its key. An existing
 * entry is byte-verified (idempotent), never overwritten; a mismatch is
 * corruption. False with err set (the caller fails the run closed). */
static bool pv_fast_cache_store(struct pv_plan_ctx *ctx,
                                const char *cache_dir, const uint8_t key[32],
                                const char *profile, const char *target,
                                const uint8_t capsule_root[32],
                                const struct pv_compile_args *args,
                                const uint8_t preproc[32], const char *rel,
                                const uint8_t package_root[32],
                                const uint8_t recipe_root[32],
                                const uint8_t lock_root[32],
                                const char *obj_file, char *err,
                                size_t err_cap)
{
    char obj_path[4400], side_path[4400];
    if (!pv_fastobj_paths(cache_dir, key, obj_path, sizeof(obj_path),
                          side_path, sizeof(side_path))) {
        (void)snprintf(err, err_cap, "fast-cache path overflow");
        return false;
    }
    uint8_t newsha[32];
    uint64_t nbytes = 0;
    if (!pv_sha3_file(obj_file, newsha, &nbytes)) {
        (void)snprintf(err, err_cap,
                       "cannot hash the compiled object %.200s", obj_file);
        return false;
    }
    size_t side_len = 0;
    char *side = pv_fastobj_sidecar(ctx, profile, target, capsule_root, args,
                                    preproc, rel, package_root, recipe_root,
                                    lock_root, newsha, nbytes, &side_len);
    if (!side) {
        (void)snprintf(err, err_cap, "fast-cache sidecar assembly failed");
        return false;
    }
    struct stat st;
    if (stat(obj_path, &st) == 0 || stat(side_path, &st) == 0) {
        /* Entry materialized between the lookup and now: byte-verify,
         * never overwrite. */
        uint8_t ex[32];
        uint64_t ebytes = 0;
        size_t eslen = 0;
        uint8_t *es = pv_read_file(side_path, PV_FASTOBJ_SIDECAR_CAP,
                                   &eslen);
        bool same = pv_sha3_file(obj_path, ex, &ebytes) &&
                    memcmp(ex, newsha, 32) == 0 && ebytes == nbytes && es &&
                    eslen == side_len && memcmp(es, side, eslen) == 0;
        free(es);
        free(side);
        if (!same) {
            (void)snprintf(err, err_cap,
                           "fast cache CORRUPTION: existing entry %.200s "
                           "differs from the freshly compiled object",
                           obj_path);
            return false;
        }
        return true;
    }
    /* Shard dir, then temp + fsync + rename for both members. */
    char shard[4400];
    (void)snprintf(shard, sizeof(shard), "%s", obj_path);
    char *slash = strrchr(shard, '/');
    if (!slash) {
        free(side);
        (void)snprintf(err, err_cap, "cannot derive the cache shard dir");
        return false;
    }
    *slash = '\0';
    if (!pv_mkdir_p(shard, 0700)) {
        free(side);
        (void)snprintf(err, err_cap, "cannot create the cache shard dir");
        return false;
    }
    char tmp[4400];
    int tn = snprintf(tmp, sizeof(tmp), "%s.zvtmp.%ld", obj_path,
                      (long)getpid());
    if (tn <= 0 || (size_t)tn >= sizeof(tmp) ||
        !pv_copy_file(obj_file, tmp, 0444) || rename(tmp, obj_path) != 0) {
        (void)unlink(tmp);
        free(side);
        (void)snprintf(err, err_cap, "cannot store cached object %.200s",
                       obj_path);
        return false;
    }
    if (!pv_atomic_write(side_path, (const uint8_t *)side, side_len)) {
        free(side);
        (void)snprintf(err, err_cap, "cannot store sidecar %.200s",
                       side_path);
        return false;
    }
    free(side);
    return true;
}

/* The ZBuild V1 action is deliberately narrower than package verification:
 * one already-preprocessed public C23 translation unit enters, one ELF
 * relocatable object leaves. No recipe, shell, response file, plugin,
 * network, arbitrary compiler, or arbitrary output name is representable. */
static int pv_zbuild_compile_mode(int argc, char **argv)
{
    const char *input_arg = NULL;
    const char *output_arg = NULL;
    bool require_full = false;
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--zbuild-input=", 15) == 0)
            input_arg = argv[i] + 15;
        else if (strncmp(argv[i], "--zbuild-output=", 16) == 0)
            output_arg = argv[i] + 16;
        else if (strcmp(argv[i], "--require-full-isolation") == 0)
            require_full = true;
        else {
            fprintf(stdout, "zbuild-error=unexpected-argument\n");
            return 2;
        }
    }
    if (!input_arg || !output_arg || !require_full || input_arg[0] != '/' ||
        output_arg[0] != '/') {
        fprintf(stdout, "zbuild-error=fixed-mode-requires-absolute-paths-and-full-isolation\n");
        return 2;
    }
    const char *input_base = strrchr(input_arg, '/');
    const char *output_base = strrchr(output_arg, '/');
    if (!input_base || strcmp(input_base + 1, "unit.i") != 0 ||
        !output_base || strcmp(output_base + 1, VCS_BUILD_OUTPUT_V1) != 0) {
        fprintf(stdout, "zbuild-error=fixed-path-policy\n");
        return 2;
    }
    char input[4096];
    if (!realpath(input_arg, input)) {
        fprintf(stdout, "zbuild-error=input-unavailable\n");
        return 3;
    }
    struct stat input_st;
    if (stat(input, &input_st) != 0 || !S_ISREG(input_st.st_mode) ||
        input_st.st_size <= 0 ||
        (uint64_t)input_st.st_size > VCS_BUILD_ARTIFACT_MAX_BYTES) {
        fprintf(stdout, "zbuild-error=input-invalid-or-oversize\n");
        return 3;
    }
    char src_dir[4096];
    (void)snprintf(src_dir, sizeof(src_dir), "%s", input);
    char *src_slash = strrchr(src_dir, '/');
    if (!src_slash) return 2;
    *src_slash = '\0';

    char output_parent_arg[4096];
    size_t parent_len = (size_t)(output_base - output_arg);
    if (parent_len == 0 || parent_len >= sizeof(output_parent_arg))
        return 2;
    memcpy(output_parent_arg, output_arg, parent_len);
    output_parent_arg[parent_len] = '\0';
    char build_dir[4096];
    if (!realpath(output_parent_arg, build_dir) ||
        strcmp(src_dir, build_dir) == 0) {
        fprintf(stdout, "zbuild-error=separate-source-and-output-dirs-required\n");
        return 3;
    }
    char output[4200];
    int on = snprintf(output, sizeof(output), "%s/%s", build_dir,
                      VCS_BUILD_OUTPUT_V1);
    if (on <= 0 || (size_t)on >= sizeof(output) || access(output, F_OK) == 0) {
        fprintf(stdout, "zbuild-error=output-must-not-exist\n");
        return 3;
    }
    if (os_sandbox_landlock_abi() < 1) {
        fprintf(stdout, "zbuild-error=landlock-unavailable\n");
        return 4;
    }

    char home_dir[4200];
    int hn = snprintf(home_dir, sizeof(home_dir), "%s/.home", src_dir);
    if (hn <= 0 || (size_t)hn >= sizeof(home_dir) ||
        mkdir(home_dir, 0500) != 0) {
        fprintf(stdout, "zbuild-error=fresh-home-unavailable\n");
        return 5;
    }

    struct os_sandbox_path_rule rules[10];
    size_t n_rules = pv_child_grants(src_dir, build_dir, NULL, 0, rules,
                                     sizeof(rules) / sizeof(rules[0]));
    if (n_rules == 0) {
        fprintf(stdout, "zbuild-error=grant-construction-failed\n");
        return 5;
    }
    const struct os_sandbox_rlimits limits = {
        .as_bytes = UINT64_C(2048) * 1024u * 1024u,
        .cpu_seconds = 120,
        .nproc = PV_ZBUILD_COMPILE_NPROC,
        .fsize_bytes = PV_COMPILE_FSIZE_BYTES,
        .nofile = PV_ZBUILD_COMPILE_NOFILE,
        .core_bytes = 0,
    };
    char env_tmpdir[4200], env_home[4200];
    (void)snprintf(env_tmpdir, sizeof(env_tmpdir), "TMPDIR=%s", build_dir);
    (void)snprintf(env_home, sizeof(env_home), "HOME=%s", home_dir);
    const char *const env[] = {
        env_tmpdir, env_home, "LANG=C", "TZ=UTC", "SOURCE_DATE_EPOCH=0",
        NULL,
    };
    const char *const cc_argv[] = {
        VCS_BUILD_COMPILER_V1, "-x", "cpp-output", "-std=c23", "-O2",
        "-march=x86-64-v3", "-fno-ident", "-c", input, "-o", output, NULL,
    };
    uint8_t input_before[32], input_after[32];
    uint64_t input_before_bytes = 0, input_after_bytes = 0;
    if (!pv_sha3_file(input, input_before, &input_before_bytes)) {
        fprintf(stdout, "zbuild-error=input-observation-failed\n");
        return 5;
    }
    struct pv_run run = pv_run_child(cc_argv, build_dir, &limits, true,
                                     rules, n_rules, env,
                                     PV_COMPILE_TIMEOUT_MS);
    int wedged = pv_report_process_failure(&run, "zbuild-error", true);
    if (wedged) {
        (void)unlink(output);
        return wedged;
    }
    if (!run.launched || run.timed_out || run.sandbox_fail || !run.exited ||
        run.exit_code != 0) {
        fprintf(stdout, "zbuild-error=%s exit=%d signal=%d diagnostics=%.512s\n",
                run.timed_out ? "timeout" :
                run.sandbox_fail ? "sandbox" : "compile",
                run.exit_code, run.term_signal, run.stderr_buf);
        (void)unlink(output);
        return 5;
    }
    struct stat output_st;
    bool output_shape = stat(output, &output_st) == 0 &&
        S_ISREG(output_st.st_mode) && output_st.st_size > 0 &&
        (uint64_t)output_st.st_size <= VCS_BUILD_ARTIFACT_MAX_BYTES;
    bool output_read_only = output_shape && chmod(output, 0400) == 0;
    bool input_stable = pv_sha3_file(
        input, input_after, &input_after_bytes) &&
        input_before_bytes == input_after_bytes &&
        memcmp(input_before, input_after, 32) == 0;
    bool writes_exact = pv_directory_has_exact_files(
        build_dir, VCS_BUILD_OUTPUT_V1, NULL);
    bool home_empty = pv_directory_is_empty(home_dir);
    if (!output_shape || !output_read_only || !input_stable ||
        !writes_exact || !home_empty) {
        fprintf(stdout,
                "zbuild-error=physical-observation-refused output=%d "
                "readonly=%d input_stable=%d writes=%d home=%d\n",
                output_shape ? 1 : 0, output_read_only ? 1 : 0,
                input_stable ? 1 : 0, writes_exact ? 1 : 0,
                home_empty ? 1 : 0);
        (void)unlink(output);
        return 5;
    }
    char input_sha3_hex[65];
    zcl_hex_encode(input_after, 32, input_sha3_hex);
    fprintf(stdout,
            "zbuild-ok=1 landlock=1 seccomp=1 rlimits=1 network=0 "
            "compiler=%s bytes=%lld input_sha3=%s observed_reads=2 "
            "observed_writes=1\n",
            VCS_BUILD_COMPILER_V1, (long long)output_st.st_size,
            input_sha3_hex);
    return 0;
}

static bool pv_zbuild_test_elf(const char *path)
{
    uint8_t header[20];
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    size_t got = fread(header, 1, sizeof(header), f);
    bool close_ok = fclose(f) == 0;
    bool ok = got == sizeof(header) && close_ok &&
        header[0] == 0x7f && header[1] == 'E' &&
        header[2] == 'L' && header[3] == 'F' && header[4] == 2 &&
        header[5] == 1 && header[6] == 1 &&
        (header[16] == 2 || header[16] == 3) && header[17] == 0 &&
        header[18] == 62 && header[19] == 0;
    return ok;
}

static bool pv_zbuild_test_write_evidence(
    const char *path, const struct pv_run *run)
{
    uint8_t wire[PV_ZBUILD_TEST_EVIDENCE_BYTES] = {0};
    memcpy(wire, "ZCTEST\r\n", 8);
    wire[8] = 1;
    wire[10] = run->exited && run->exit_code == 0 && !run->timed_out &&
                       run->term_signal == 0
        ? 1 : 2;
    wire[11] = (run->timed_out ? 1u : 0u) |
               (run->stdout_truncated ? 2u : 0u) |
               (run->stderr_truncated ? 4u : 0u);
    uint32_t exit_code = run->exited ? (uint32_t)run->exit_code : UINT32_MAX;
    uint32_t signal = run->term_signal > 0
        ? (uint32_t)run->term_signal : 0;
    zcl_write_u32_le(wire + 12, exit_code);
    zcl_write_u32_le(wire + 16, signal);
    sha3_256((const uint8_t *)run->stdout_buf, run->stdout_len,
             wire + 20);
    sha3_256((const uint8_t *)run->stderr_buf, run->stderr_len,
             wire + 52);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0400);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < sizeof(wire)) {
        ssize_t wrote = write(fd, wire + off, sizeof(wire) - off);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) break;
        off += (size_t)wrote;
    }
    bool synced = off == sizeof(wire) && fsync(fd) == 0;
    bool ok = close(fd) == 0 && synced;
    if (!ok) (void)unlink(path);
    return ok;
}

/* One exact executable, no argv, no shell, no network. The parent worker
 * supplied and hashed the bytes; this process only confines execution and
 * emits the closed verdict wire. Test failures/timeouts are evidence and
 * therefore return zero after a report is written. Sandbox failures do not. */
static int pv_zbuild_test_mode(int argc, char **argv)
{
    const char *input_arg = NULL, *output_arg = NULL;
    bool require_full = false;
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--zbuild-test-input=", 20) == 0)
            input_arg = argv[i] + 20;
        else if (strncmp(argv[i], "--zbuild-test-output=", 21) == 0)
            output_arg = argv[i] + 21;
        else if (strcmp(argv[i], "--require-full-isolation") == 0)
            require_full = true;
        else {
            fprintf(stdout, "zbuild-test-error=unexpected-argument\n");
            return 2;
        }
    }
    if (!input_arg || !output_arg || !require_full || input_arg[0] != '/' ||
        output_arg[0] != '/')
        return 2;
    const char *input_base = strrchr(input_arg, '/');
    const char *output_base = strrchr(output_arg, '/');
    if (!input_base || strcmp(input_base + 1, "test.bin") != 0 ||
        !output_base || strcmp(output_base + 1, "test.evidence.v1") != 0)
        return 2;
    char input[4096];
    if (!realpath(input_arg, input) || !pv_zbuild_test_elf(input))
        return 3;
    char build_arg[4096];
    size_t build_len = (size_t)(output_base - output_arg);
    if (build_len == 0 || build_len >= sizeof(build_arg)) return 2;
    memcpy(build_arg, output_arg, build_len);
    build_arg[build_len] = '\0';
    char build_dir[4096];
    if (!realpath(build_arg, build_dir)) return 3;
    char output[4200];
    int n = snprintf(output, sizeof(output), "%s/test.evidence.v1",
                     build_dir);
    if (n <= 0 || (size_t)n >= sizeof(output) || access(output, F_OK) == 0)
        return 3;
    char input_dir[4096];
    (void)snprintf(input_dir, sizeof(input_dir), "%s", input);
    char *input_slash = strrchr(input_dir, '/');
    if (!input_slash || input_slash == input_dir) return 3;
    *input_slash = '\0';
    if (strcmp(input_dir, build_dir) != 0) return 3;
    if (os_sandbox_landlock_abi() < 1) return 4;
    struct os_sandbox_path_rule rules[10];
    size_t n_rules = pv_child_grants(build_dir, build_dir, NULL, 0, rules,
                                     sizeof(rules) / sizeof(rules[0]));
    if (n_rules == 0) return 5;
    const struct os_sandbox_rlimits limits = {
        .as_bytes = UINT64_C(2048) * 1024u * 1024u,
        .cpu_seconds = 600,
        .nproc = PV_TEST_NPROC,
        .fsize_bytes = PV_TEST_FSIZE_BYTES,
        .nofile = PV_TEST_NOFILE,
        .core_bytes = 0,
    };
    char env_tmpdir[4200];
    (void)snprintf(env_tmpdir, sizeof(env_tmpdir), "TMPDIR=%s", build_dir);
    const char *const env[] = { env_tmpdir, NULL };
    const char *const test_argv[] = { input, NULL };
    struct pv_run run = pv_run_child(
        test_argv, build_dir, &limits, true, rules, n_rules, env,
        PV_ZBUILD_TEST_TIMEOUT_MS);
    /* Untrusted child: never sniff its stderr for a wedge (trusted_child
     * false). A SUBTREE over budget is real evidence about this binary and
     * is written as a fail verdict below; only the pre-fork host refusal
     * short-circuits, because then nothing ran and there is no evidence. */
    if (run.headroom_exhausted) {
        int wedged = pv_report_process_failure(
            &run, "zbuild-test-error", false);
        (void)unlink(output);
        return wedged;
    }
    if (!run.launched || run.sandbox_fail ||
        !pv_zbuild_test_write_evidence(output, &run)) {
        (void)unlink(output);
        return 5;
    }
    fprintf(stdout,
            "zbuild-test-ok=1 verdict=%s exit=%d signal=%d timeout=%d "
            "landlock=1 seccomp=1 rlimits=1 network=0\n",
            run.exited && run.exit_code == 0 && !run.timed_out &&
                    run.term_signal == 0
                ? "pass" : "fail",
            run.exit_code, run.term_signal, run.timed_out ? 1 : 0);
    return 0;
}

/* Fixed deterministic fuzz ABI: execute one exact ELF for seeds [0,N), with
 * the sole argv "--seed=<u32>" and matching ZCODE_FUZZ_SEED. The environment
 * is otherwise scrubbed by pv_run_child. A target failure is evidence; a
 * confinement/launch failure is not. */
static int pv_zbuild_fuzz_mode(int argc, char **argv)
{
    const char *input_arg = NULL, *output_arg = NULL, *seeds_arg = NULL;
    const char *cpu_arg = NULL, *memory_arg = NULL, *output_limit_arg = NULL;
    bool require_full = false;
    for (int i = 1; i < argc; i++) {
        static const char in_prefix[] = "--zbuild-fuzz-input=";
        static const char out_prefix[] = "--zbuild-fuzz-output=";
        static const char seeds_prefix[] = "--zbuild-fuzz-seeds=";
        static const char cpu_prefix[] = "--zbuild-fuzz-cpu-seconds=";
        static const char memory_prefix[] = "--zbuild-fuzz-memory-bytes=";
        static const char output_limit_prefix[] =
            "--zbuild-fuzz-output-bytes=";
        if (strncmp(argv[i], in_prefix, sizeof(in_prefix) - 1u) == 0)
            input_arg = argv[i] + sizeof(in_prefix) - 1u;
        else if (strncmp(argv[i], out_prefix, sizeof(out_prefix) - 1u) == 0)
            output_arg = argv[i] + sizeof(out_prefix) - 1u;
        else if (strncmp(argv[i], seeds_prefix,
                         sizeof(seeds_prefix) - 1u) == 0)
            seeds_arg = argv[i] + sizeof(seeds_prefix) - 1u;
        else if (strncmp(argv[i], cpu_prefix,
                         sizeof(cpu_prefix) - 1u) == 0)
            cpu_arg = argv[i] + sizeof(cpu_prefix) - 1u;
        else if (strncmp(argv[i], memory_prefix,
                         sizeof(memory_prefix) - 1u) == 0)
            memory_arg = argv[i] + sizeof(memory_prefix) - 1u;
        else if (strncmp(argv[i], output_limit_prefix,
                         sizeof(output_limit_prefix) - 1u) == 0)
            output_limit_arg = argv[i] + sizeof(output_limit_prefix) - 1u;
        else if (strcmp(argv[i], "--require-full-isolation") == 0)
            require_full = true;
        else
            return 2;
    }
    char *end = NULL;
    unsigned long seeds_ul = seeds_arg ? strtoul(seeds_arg, &end, 10) : 0;
    if (!input_arg || !output_arg || !require_full || !seeds_arg ||
        !end || *end != '\0' || seeds_ul == 0 ||
        seeds_ul > VCS_ZCODE_FUZZ_SEEDS_MAX || input_arg[0] != '/' ||
        output_arg[0] != '/')
        return 2;
    char *cpu_end = NULL, *memory_end = NULL, *output_limit_end = NULL;
    unsigned long cpu_ul = cpu_arg ? strtoul(cpu_arg, &cpu_end, 10) : 0;
    unsigned long long memory_ull = memory_arg
        ? strtoull(memory_arg, &memory_end, 10) : 0;
    unsigned long long output_limit_ull = output_limit_arg
        ? strtoull(output_limit_arg, &output_limit_end, 10) : 0;
    if (!cpu_arg || !cpu_end || *cpu_end != '\0' || cpu_ul == 0 ||
        cpu_ul > 600u || !memory_arg || !memory_end || *memory_end != '\0' ||
        memory_ull == 0 || memory_ull > UINT64_C(2048) * 1024u * 1024u ||
        !output_limit_arg || !output_limit_end || *output_limit_end != '\0' ||
        output_limit_ull == 0 ||
        output_limit_ull > UINT64_C(64) * 1024u * 1024u)
        return 2;
    uint32_t seeds = (uint32_t)seeds_ul;
    const char *input_base = strrchr(input_arg, '/');
    const char *output_base = strrchr(output_arg, '/');
    if (!input_base || strcmp(input_base + 1, "fuzz.bin") != 0 ||
        !output_base || strcmp(output_base + 1, VCS_BUILD_FUZZ_OUTPUT_V1) != 0)
        return 2;
    char input[4096];
    if (!realpath(input_arg, input) || !pv_zbuild_test_elf(input)) return 3;
    char build_arg[4096];
    size_t build_len = (size_t)(output_base - output_arg);
    if (build_len == 0 || build_len >= sizeof(build_arg)) return 2;
    memcpy(build_arg, output_arg, build_len); build_arg[build_len] = '\0';
    char build_dir[4096];
    if (!realpath(build_arg, build_dir)) return 3;
    char output[4200];
    int on = snprintf(output, sizeof(output), "%s/%s", build_dir,
                      VCS_BUILD_FUZZ_OUTPUT_V1);
    if (on <= 0 || (size_t)on >= sizeof(output) || access(output, F_OK) == 0)
        return 3;
    char input_dir[4096];
    (void)snprintf(input_dir, sizeof(input_dir), "%s", input);
    char *slash = strrchr(input_dir, '/');
    if (!slash || slash == input_dir) return 3;
    *slash = '\0';
    if (strcmp(input_dir, build_dir) != 0 || os_sandbox_landlock_abi() < 1)
        return 4;
    struct os_sandbox_path_rule rules[10];
    size_t n_rules = pv_child_grants(build_dir, build_dir, NULL, 0, rules,
                                     sizeof(rules) / sizeof(rules[0]));
    if (n_rules == 0) return 5;
    uint64_t per_seed_cpu = (cpu_ul + seeds - 1u) / seeds;
    if (per_seed_cpu == 0) per_seed_cpu = 1;
    const struct os_sandbox_rlimits limits = {
        .as_bytes = (uint64_t)memory_ull,
        .cpu_seconds = per_seed_cpu,
        .nproc = PV_TEST_NPROC,
        .fsize_bytes = (uint64_t)output_limit_ull,
        .nofile = PV_TEST_NOFILE,
        .core_bytes = 0,
    };
    int total_timeout_ms = (int)cpu_ul * 1000;
    int per_seed_timeout = total_timeout_ms / (int)seeds;
    if (per_seed_timeout < 100) per_seed_timeout = 100;
    struct sha3_256_ctx stdout_sha, stderr_sha;
    sha3_256_init(&stdout_sha); sha3_256_init(&stderr_sha);
    static const char stdout_domain[] = "zcl.zcode.fuzz.stdout.v1";
    static const char stderr_domain[] = "zcl.zcode.fuzz.stderr.v1";
    sha3_256_write(&stdout_sha, (const uint8_t *)stdout_domain,
                   sizeof(stdout_domain));
    sha3_256_write(&stderr_sha, (const uint8_t *)stderr_domain,
                   sizeof(stderr_domain));
    uint8_t status = 1, flags = 0;
    uint32_t completed = 0, failing_seed = UINT32_MAX;
    uint32_t exit_code = 0, signal_code = 0;
    for (uint32_t seed = 0; seed < seeds; seed++) {
        char seed_argv[48], seed_env[64], env_tmpdir[4200];
        (void)snprintf(seed_argv, sizeof(seed_argv), "--seed=%u", seed);
        (void)snprintf(seed_env, sizeof(seed_env),
                       "ZCODE_FUZZ_SEED=%u", seed);
        (void)snprintf(env_tmpdir, sizeof(env_tmpdir), "TMPDIR=%s", build_dir);
        const char *const env[] = { env_tmpdir, seed_env, NULL };
        const char *const fuzz_argv[] = { input, seed_argv, NULL };
        struct pv_run run = pv_run_child(
            fuzz_argv, build_dir, &limits, true, rules, n_rules, env,
            per_seed_timeout);
        /* See the test-mode note: a host refusal is not fuzz evidence. */
        if (run.headroom_exhausted)
            return pv_report_process_failure(&run, "zbuild-fuzz-error", false);
        if (!run.launched || run.sandbox_fail) return 5;
        uint8_t meta[8];
        zcl_write_u32_le(meta, seed);
        zcl_write_u32_le(meta + 4, (uint32_t)run.stdout_len);
        sha3_256_write(&stdout_sha, meta, sizeof(meta));
        sha3_256_write(&stdout_sha, (const uint8_t *)run.stdout_buf,
                       run.stdout_len);
        zcl_write_u32_le(meta + 4, (uint32_t)run.stderr_len);
        sha3_256_write(&stderr_sha, meta, sizeof(meta));
        sha3_256_write(&stderr_sha, (const uint8_t *)run.stderr_buf,
                       run.stderr_len);
        completed = seed + 1u;
        flags |= (run.timed_out ? 1u : 0u) |
                 (run.stdout_truncated ? 2u : 0u) |
                 (run.stderr_truncated ? 4u : 0u);
        if (!run.exited || run.exit_code != 0 || run.term_signal != 0 ||
            run.timed_out) {
            status = 2; failing_seed = seed;
            exit_code = run.exited ? (uint32_t)run.exit_code : UINT32_MAX;
            signal_code = run.term_signal > 0
                ? (uint32_t)run.term_signal : 0;
            break;
        }
    }
    uint8_t wire[PV_ZBUILD_FUZZ_EVIDENCE_BYTES] = {0};
    memcpy(wire, "ZCFUZZ\r\n", 8); wire[8] = 1; wire[10] = status;
    wire[11] = flags;
    zcl_write_u32_le(wire + 12, seeds);
    zcl_write_u32_le(wire + 16, completed);
    zcl_write_u32_le(wire + 20, failing_seed);
    zcl_write_u32_le(wire + 24, exit_code);
    zcl_write_u32_le(wire + 28, signal_code);
    sha3_256_finalize(&stdout_sha, wire + 32);
    sha3_256_finalize(&stderr_sha, wire + 64);
    int fd = open(output, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0400);
    if (fd < 0) return 5;
    size_t off = 0;
    while (off < sizeof(wire)) {
        ssize_t wrote = write(fd, wire + off, sizeof(wire) - off);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) break;
        off += (size_t)wrote;
    }
    bool synced = off == sizeof(wire) && fsync(fd) == 0;
    bool wrote = close(fd) == 0 && synced;
    if (!wrote) { (void)unlink(output); return 5; }
    fprintf(stdout,
            "zbuild-fuzz-ok=1 verdict=%s seeds=%u completed=%u "
            "landlock=1 seccomp=1 rlimits=1 network=0\n",
            status == 1 ? "pass" : "fail", seeds, completed);
    return 0;
}

/* ── main flow ──────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++)
        if (strncmp(argv[i], "--zbuild-fuzz-input=", 20) == 0)
            return pv_zbuild_fuzz_mode(argc, argv);
    for (int i = 1; i < argc; i++)
        if (strncmp(argv[i], "--zbuild-test-input=", 20) == 0)
            return pv_zbuild_test_mode(argc, argv);
    for (int i = 1; i < argc; i++)
        if (strncmp(argv[i], "--zbuild-input=", 15) == 0)
            return pv_zbuild_compile_mode(argc, argv);
    const char *root_hex = NULL;
    const char *store_dir = NULL;
    const char *key_path = NULL;
    const char *work_parent = NULL;
    const char *emit_dir = NULL;
    const char *lock_root_hex = NULL;
    const char *reproduce_path = NULL;
    const char *plan_path = NULL;
    const char *fast_cache_dir = NULL;
    const char *candidate_source_arg = NULL;
    const char *candidate_recipe_arg = NULL;
    const char *candidate_name = NULL;
    const char *candidate_profile = NULL;
    const char *candidate_cpu_arg = NULL;
    bool require_full_isolation = false;
    bool allow_testless_standard = false;
    struct pv_emit_dep emit_deps[PV_EMIT_MAX_DEPS];
    size_t emit_dep_count = 0;
    memset(emit_deps, 0, sizeof(emit_deps));
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--store=", 8) == 0)
            store_dir = argv[i] + 8;
        else if (strncmp(argv[i], "--key=", 6) == 0)
            key_path = argv[i] + 6;
        else if (strncmp(argv[i], "--work=", 7) == 0)
            work_parent = argv[i] + 7;
        else if (strncmp(argv[i], "--emit=", 7) == 0)
            emit_dir = argv[i] + 7;
        else if (strncmp(argv[i], "--lock-root=", 12) == 0)
            lock_root_hex = argv[i] + 12;
        else if (strncmp(argv[i], "--reproduce-against=", 20) == 0)
            reproduce_path = argv[i] + 20;
        else if (strncmp(argv[i], "--plan=", 7) == 0)
            plan_path = argv[i] + 7;
        else if (strncmp(argv[i], "--fast-cache=", 13) == 0)
            fast_cache_dir = argv[i] + 13;
        else if (strncmp(argv[i], "--zbuild-package-source=", 24) == 0)
            candidate_source_arg = argv[i] + 24;
        else if (strncmp(argv[i], "--zbuild-package-recipe=", 24) == 0)
            candidate_recipe_arg = argv[i] + 24;
        else if (strncmp(argv[i], "--zbuild-package-name=", 22) == 0)
            candidate_name = argv[i] + 22;
        else if (strncmp(argv[i], "--zbuild-package-profile=", 25) == 0)
            candidate_profile = argv[i] + 25;
        else if (strncmp(argv[i], "--zbuild-package-max-cpu-seconds=", 33) == 0)
            candidate_cpu_arg = argv[i] + 33;
        else if (strncmp(argv[i], "--dep=", 6) == 0) {
            /* <64 hex>,<install dir> — the hex is fixed-width, so the comma
             * position is unambiguous even if the path contains commas. */
            const char *spec = argv[i] + 6;
            if (emit_dep_count >= PV_EMIT_MAX_DEPS) {
                fprintf(stderr, "%s: more than %u --dep entries\n", PV_LOG,
                        PV_EMIT_MAX_DEPS);
                return 2;
            }
            struct pv_emit_dep *d = &emit_deps[emit_dep_count];
            char hex[65];
            if (strlen(spec) < 66u || spec[64] != ',') {
                fprintf(stderr, "%s: --dep wants <64hex>,<install-dir>\n",
                        PV_LOG);
                return 2;
            }
            memcpy(hex, spec, 64);
            hex[64] = '\0';
            if (!zcl_hex_decode(hex, d->root, 32)) {
                fprintf(stderr, "%s: --dep root is not 64 hex chars\n",
                        PV_LOG);
                return 2;
            }
            int dn = snprintf(d->install_dir, sizeof(d->install_dir), "%s",
                              spec + 65);
            if (dn <= 0 || (size_t)dn >= sizeof(d->install_dir)) {
                fprintf(stderr, "%s: --dep install dir too long\n", PV_LOG);
                return 2;
            }
            /* Canonicalize to an ABSOLUTE path, same reason as --work above:
             * build children chdir() into build_root before their Landlock
             * grants (which now include every --dep install dir) are opened,
             * so a relative --dep path resolves against the wrong cwd and
             * the grant silently 404s (ENOENT), never against the caller's
             * actual directory. */
            char dep_resolved[4096]; /* realpath(3) requires >= PATH_MAX */
            if (!realpath(d->install_dir, dep_resolved)) {
                fprintf(stderr, "%s: cannot resolve --dep install dir %s: %s\n",
                        PV_LOG, d->install_dir, strerror(errno));
                return 2;
            }
            snprintf(d->install_dir, sizeof(d->install_dir), "%s",
                     dep_resolved);
            int in = snprintf(d->include_dir, sizeof(d->include_dir),
                              "%s/include", dep_resolved);
            if (in <= 0 || (size_t)in >= sizeof(d->include_dir)) {
                fprintf(stderr, "%s: --dep install dir too long\n", PV_LOG);
                return 2;
            }
            emit_dep_count++;
        } else if (strcmp(argv[i], "--require-full-isolation") == 0)
            require_full_isolation = true;
        else if (strcmp(argv[i], "--allow-testless-standard") == 0)
            allow_testless_standard = true;
        else if (strcmp(argv[i], "--help") == 0 ||
                 strcmp(argv[i], "-h") == 0) {
            pv_usage(stdout);
            return 0;
        } else if (argv[i][0] != '-' && !root_hex)
            root_hex = argv[i];
        else {
            pv_usage(stderr);
            return 2;
        }
    }
    bool candidate_mode = candidate_source_arg != NULL ||
                          candidate_recipe_arg != NULL ||
                          candidate_name != NULL ||
                          candidate_profile != NULL ||
                          candidate_cpu_arg != NULL;
    bool standard_profile = candidate_profile &&
                            strcmp(candidate_profile, "standard") == 0;
    bool known_candidate_profile = candidate_profile &&
        (standard_profile || strcmp(candidate_profile, "quick") == 0);
    char *candidate_cpu_end = NULL;
    errno = 0;
    unsigned long long candidate_cpu_seconds = candidate_cpu_arg
        ? strtoull(candidate_cpu_arg, &candidate_cpu_end, 10) : 0;
    bool candidate_cpu_valid = candidate_cpu_arg && candidate_cpu_arg[0] &&
        candidate_cpu_end && *candidate_cpu_end == '\0' && errno == 0 &&
        candidate_cpu_seconds >= 1 && candidate_cpu_seconds <= 600;
    /* The modes are mutually exclusive: an emit run signs nothing, so a
     * key would only invite the belief that its output was attested.
     * --reproduce-against belongs to emit mode: it is the byte-identity
     * check of THIS build's receipt against a reference build-report. */
    bool normal_shape = !candidate_mode && root_hex && store_dir &&
        (key_path || emit_dir) && !(key_path && emit_dir) &&
        (!emit_dir || lock_root_hex) &&
        (emit_dir || (!lock_root_hex && emit_dep_count == 0 &&
                      !reproduce_path)) &&
        (!plan_path || emit_dir) && !fast_cache_dir;
    bool candidate_shape = candidate_mode && root_hex && !store_dir &&
        !key_path && emit_dir && lock_root_hex && candidate_source_arg &&
        candidate_recipe_arg && candidate_name && candidate_name[0] &&
        known_candidate_profile && candidate_cpu_valid &&
        !reproduce_path && require_full_isolation &&
        (!plan_path || emit_dir);
    if (!normal_shape && !candidate_shape) {
        pv_usage(stderr);
        return 2;
    }
    if (candidate_shape)
        g_pv_cpu_budget_us = (uint64_t)candidate_cpu_seconds *
                             UINT64_C(1000000);
    uint8_t emit_lock_root[32] = { 0 };
    if (emit_dir && !zcl_hex_decode(lock_root_hex, emit_lock_root, 32)) {
        fprintf(stderr, "%s: --lock-root wants 64 hex chars\n", PV_LOG);
        return 2;
    }
    uint8_t package_root[32];
    if (!zcl_hex_decode(root_hex, package_root, 32)) {
        fprintf(stderr, "%s: bad package root (want 64 hex)\n", PV_LOG);
        return 2;
    }
    char candidate_source[4096] = {0};
    char candidate_recipe[4096] = {0};
    struct stat st;
    if (candidate_mode &&
        (!realpath(candidate_source_arg, candidate_source) ||
         !realpath(candidate_recipe_arg, candidate_recipe))) {
        fprintf(stderr, "%s: candidate source or recipe cannot resolve\n",
                PV_LOG);
        return 3;
    }
    if (candidate_mode &&
        (stat(candidate_source, &st) != 0 || !S_ISDIR(st.st_mode) ||
         stat(candidate_recipe, &st) != 0 || !S_ISREG(st.st_mode))) {
        fprintf(stderr, "%s: candidate source/recipe shape refused\n",
                PV_LOG);
        return 3;
    }

    /* Isolation probe FIRST: it decides full vs degraded before any work. */
    const bool landlock = os_sandbox_landlock_abi() >= 1;
    if (!landlock) {
        if (require_full_isolation) {
            fprintf(stderr,
                    "%s: FATAL: --require-full-isolation and this kernel "
                    "offers no Landlock — failing closed, nothing signed\n",
                    PV_LOG);
            return 4;
        }
        fprintf(stderr,
                "%s: WARNING: Landlock unavailable on this kernel — running "
                "DEGRADED (no filesystem scoping; seccomp + rlimits still "
                "deny network and bound resources). The attestation will "
                "carry isolation=degraded.\n", PV_LOG);
    }

    /* Store layout sanity. Candidate mode has no release store: the parent
     * already proved the task/candidate/recipe/lock CAS bindings. */
    char probe[4096];
    static const char *const k_need[] = {
        "/manifests", "/releases", "/recipes", "/cas/sha3",
    };
    for (size_t i = 0; !candidate_mode &&
                         i < sizeof(k_need) / sizeof(k_need[0]); i++) {
        int n = snprintf(probe, sizeof(probe), "%s%s", store_dir, k_need[i]);
        if (n < 0 || (size_t)n >= sizeof(probe) ||
            stat(probe, &st) != 0 || !S_ISDIR(st.st_mode)) {
            fprintf(stderr, "%s: %s%s: not a package store directory\n",
                    PV_LOG, store_dir, k_need[i]);
            return 3;
        }
    }
    if (!candidate_mode && !emit_dir) {
        int n = snprintf(probe, sizeof(probe), "%s/attestations", store_dir);
        if (n < 0 || (size_t)n >= sizeof(probe) || !pv_mkdir_p(probe, 0700)) {
            fprintf(stderr, "%s: cannot create %s/attestations\n", PV_LOG,
                    store_dir);
            return 3;
        }
    }

    /* Verifier key — attestation mode only. An emit run signs nothing, so it
     * never reads a secret; the caller re-hashes the outputs instead. */
    secp256k1_context *sign_ctx = NULL;
    uint8_t secret[32] = { 0 };
    uint8_t verifier_pubkey[33] = { 0 };
    if (!emit_dir) {
        struct stat kst;
        if (stat(key_path, &kst) != 0 || !S_ISREG(kst.st_mode) ||
            (kst.st_mode & 077) != 0) {
            fprintf(stderr,
                    "%s: key file %s must be a regular file with no "
                    "group/other permission bits (0600 or 0400)\n",
                    PV_LOG, key_path);
            return 3;
        }
        size_t key_len = 0;
        uint8_t *key_text = pv_read_file(key_path, 128, &key_len);
        if (!key_text) {
            fprintf(stderr, "%s: cannot read key file %s\n", PV_LOG,
                    key_path);
            return 3;
        }
        while (key_len > 0 &&
               (key_text[key_len - 1] == '\n' ||
                key_text[key_len - 1] == '\r' ||
                key_text[key_len - 1] == ' ' ||
                key_text[key_len - 1] == '\t'))
            key_len--;
        char key_hex[65];
        if (key_len != 64) {
            fprintf(stderr, "%s: key file must hold exactly 64 hex chars\n",
                    PV_LOG);
            free(key_text);
            return 3;
        }
        memcpy(key_hex, key_text, 64);
        key_hex[64] = '\0';
        free(key_text);
        if (!zcl_hex_decode(key_hex, secret, 32)) {
            fprintf(stderr, "%s: key file is not 64 hex chars\n", PV_LOG);
            return 3;
        }
        sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        if (!sign_ctx || !secp256k1_ec_seckey_verify(sign_ctx, secret)) {
            fprintf(stderr, "%s: key is not a valid secp256k1 secret\n",
                    PV_LOG);
            return 3;
        }
        secp256k1_pubkey vpk;
        size_t vpk_len = sizeof(verifier_pubkey);
        if (!secp256k1_ec_pubkey_create(sign_ctx, &vpk, secret) ||
            !secp256k1_ec_pubkey_serialize(sign_ctx, verifier_pubkey,
                                           &vpk_len, &vpk,
                                           SECP256K1_EC_COMPRESSED) ||
            vpk_len != sizeof(verifier_pubkey)) {
            fprintf(stderr, "%s: cannot derive the verifier pubkey\n",
                    PV_LOG);
            return 3;
        }
    }

    /* Release + manifest + recipe. */
    struct vcs_package_release release = {0};
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    struct vcs_package_recipe recipe;
    vcs_package_recipe_init(&recipe);
    uint8_t recipe_root[32] = {0};
    uint8_t release_id[32] = { 0 };
    if (candidate_mode) {
        size_t recipe_wire_len = 0;
        uint8_t *recipe_wire = pv_read_file(
            candidate_recipe, VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES,
            &recipe_wire_len);
        enum vcs_package_recipe_error rerr = recipe_wire
            ? vcs_package_recipe_parse(recipe_wire, recipe_wire_len, &recipe)
            : VCS_PACKAGE_RECIPE_ERR_WIRE_TRUNCATED;
        free(recipe_wire);
        char membership[160];
        if (rerr != VCS_PACKAGE_RECIPE_OK ||
            vcs_package_recipe_root(&recipe, recipe_root) !=
                VCS_PACKAGE_RECIPE_OK ||
            !pv_recipe_files_in_source(&recipe, candidate_source,
                                       membership, sizeof(membership))) {
            fprintf(stderr, "%s: candidate recipe/source refused: %s\n",
                    PV_LOG, rerr != VCS_PACKAGE_RECIPE_OK
                        ? vcs_package_recipe_error_string(rerr) : membership);
            vcs_package_recipe_free(&recipe);
            return 3;
        }
        int nn = snprintf(release.name, sizeof(release.name), "%s",
                          candidate_name);
        const char *slash = strchr(release.name, '/');
        char archive_path[VCS_PACKAGE_BUILD_PATH_MAX + 1u];
        int an = slash && slash[1]
            ? snprintf(archive_path, sizeof(archive_path), "lib/lib%s.a",
                       slash + 1) : -1;
        if (nn <= 0 || (size_t)nn >= sizeof(release.name) || !slash ||
            strchr(slash + 1, '/') || an <= 0 ||
            (size_t)an >= sizeof(archive_path) ||
            !vcs_package_path_valid(archive_path)) {
            fprintf(stderr, "%s: candidate package name refused\n", PV_LOG);
            vcs_package_recipe_free(&recipe);
            return 3;
        }
    } else {
    if (!pv_load_release(store_dir, package_root, &release, release_id)) {
        fprintf(stderr,
                "%s: no verified release envelope in %s/releases names "
                "this package root\n", PV_LOG, store_dir);
        return 3;
    }
    char root_hex64[65];
    zcl_hex_encode(package_root, 32, root_hex64);
    int mn = snprintf(probe, sizeof(probe), "%s/manifests/%s", store_dir,
                      root_hex64);
    size_t manifest_wire_len = 0;
    uint8_t *manifest_wire =
        mn > 0 && (size_t)mn < sizeof(probe)
            ? pv_read_file(probe, VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES,
                           &manifest_wire_len)
            : NULL;
    if (!manifest_wire) {
        fprintf(stderr, "%s: manifest for %s not hosted\n", PV_LOG,
                root_hex64);
        return 3;
    }
    if (!vcs_package_manifest_parse(manifest_wire, manifest_wire_len,
                                    &manifest)) {
        fprintf(stderr, "%s: manifest %s does not parse\n", PV_LOG,
                root_hex64);
        free(manifest_wire);
        return 3;
    }
    free(manifest_wire);
    uint8_t manifest_root[32] = { 0 };
    if (!vcs_package_manifest_root(&manifest, manifest_root) ||
        memcmp(manifest_root, package_root, 32) != 0) {
        fprintf(stderr, "%s: manifest root mismatch for %s\n", PV_LOG,
                root_hex64);
        vcs_package_manifest_free(&manifest);
        return 3;
    }
    char recipe_root_hex[65];
    zcl_hex_encode(release.recipe_root, 32, recipe_root_hex);
    int rn = snprintf(probe, sizeof(probe), "%s/recipes/%s", store_dir,
                      recipe_root_hex);
    size_t recipe_wire_len = 0;
    uint8_t *recipe_wire =
        rn > 0 && (size_t)rn < sizeof(probe)
            ? pv_read_file(probe, VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES,
                           &recipe_wire_len)
            : NULL;
    if (!recipe_wire) {
        fprintf(stderr, "%s: recipe %s not hosted\n", PV_LOG,
                recipe_root_hex);
        vcs_package_manifest_free(&manifest);
        return 3;
    }
    enum vcs_package_recipe_error rerr =
        vcs_package_recipe_parse(recipe_wire, recipe_wire_len, &recipe);
    free(recipe_wire);
    if (rerr != VCS_PACKAGE_RECIPE_OK) {
        fprintf(stderr, "%s: recipe %s does not parse: %s\n", PV_LOG,
                recipe_root_hex, vcs_package_recipe_error_string(rerr));
        vcs_package_manifest_free(&manifest);
        return 3;
    }
    if (vcs_package_recipe_root(&recipe, recipe_root) !=
            VCS_PACKAGE_RECIPE_OK ||
        memcmp(recipe_root, release.recipe_root, 32) != 0) {
        fprintf(stderr, "%s: recipe root mismatch against the envelope\n",
                PV_LOG);
        vcs_package_recipe_free(&recipe);
        vcs_package_manifest_free(&manifest);
        return 3;
    }
    char membership[160];
    if (!vcs_package_recipe_files_in_manifest(&recipe, &manifest,
                                              membership,
                                              sizeof(membership))) {
        fprintf(stderr, "%s: recipe path not in manifest: %s\n", PV_LOG,
                membership);
        vcs_package_recipe_free(&recipe);
        vcs_package_manifest_free(&manifest);
        return 3;
    }

    /* Completeness: every chunk must be in the CAS. */
    for (size_t i = 0; i < manifest.count; i++) {
        const struct vcs_package_file *f = &manifest.files[i];
        for (uint32_t c = 0; c < f->chunk_count; c++) {
            char hex[65];
            zcl_hex_encode(f->chunk_hashes + (size_t)c * 32u, 32, hex);
            int cn = snprintf(probe, sizeof(probe), "%s/cas/sha3/%.2s/%s",
                              store_dir, hex, hex);
            if (cn < 0 || (size_t)cn >= sizeof(probe) ||
                stat(probe, &st) != 0) {
                fprintf(stderr,
                        "%s: package incomplete: chunk %s#%u absent\n",
                        PV_LOG, f->path, c);
                vcs_package_recipe_free(&recipe);
                vcs_package_manifest_free(&manifest);
                return 3;
            }
        }
    }
    }

    /* Temp work tree: <work>/zclverify.XXXXXX/{src,build}. */
    if (!work_parent) {
        work_parent = getenv("TMPDIR");
        if (!work_parent || !work_parent[0])
            work_parent = "/tmp";
    }
    char work[4096];
    int wn = snprintf(work, sizeof(work), "%s/zclverify.XXXXXX",
                      work_parent);
    if (wn < 0 || (size_t)wn >= sizeof(work) || !mkdtemp(work)) {
        fprintf(stderr, "%s: cannot create temp dir under %s: %s\n", PV_LOG,
                work_parent, strerror(errno));
        vcs_package_recipe_free(&recipe);
        vcs_package_manifest_free(&manifest);
        return 5;
    }
    /* Canonicalize to an ABSOLUTE path: build children chdir() into the
     * build dir before their Landlock grants (which carry src/build paths)
     * are opened, and compiler argv carries src/build paths too — a
     * relative --work would break both. */
    {
        char resolved[4096];
        if (!realpath(work, resolved)) {
            fprintf(stderr, "%s: cannot resolve %s: %s\n", PV_LOG, work,
                    strerror(errno));
            pv_rm_rf(work);
            vcs_package_recipe_free(&recipe);
            vcs_package_manifest_free(&manifest);
            return 5;
        }
        snprintf(work, sizeof(work), "%s", resolved);
    }
    char src_root[4200];
    char build_root[4200];
    snprintf(src_root, sizeof(src_root), "%s",
             candidate_mode ? candidate_source : "");
    if (!candidate_mode)
        snprintf(src_root, sizeof(src_root), "%s/src", work);
    snprintf(build_root, sizeof(build_root), "%s/build", work);
    if ((!candidate_mode && !pv_mkdir_p(src_root, 0755)) ||
        !pv_mkdir_p(build_root, 0755)) {
        fprintf(stderr, "%s: cannot create %s/{src,build}\n", PV_LOG, work);
        pv_rm_rf(work);
        vcs_package_recipe_free(&recipe);
        vcs_package_manifest_free(&manifest);
        return 5;
    }

    /* Materialize the package read-only from the CAS. */
    bool materialized = true;
    for (size_t i = 0; !candidate_mode && i < manifest.count && materialized;
         i++) {
        const struct vcs_package_file *f = &manifest.files[i];
        char dest[4200];
        int dn = snprintf(dest, sizeof(dest), "%s/%s", src_root, f->path);
        if (dn < 0 || (size_t)dn >= sizeof(dest)) {
            materialized = false;
            break;
        }
        char parent[4200];
        snprintf(parent, sizeof(parent), "%s", dest);
        char *slash = strrchr(parent, '/');
        if (slash) {
            *slash = '\0';
            if (!pv_mkdir_p(parent, 0755)) {
                materialized = false;
                break;
            }
        }
        int fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0444);
        if (fd < 0) {
            materialized = false;
            break;
        }
        for (uint32_t c = 0; c < f->chunk_count; c++) {
            char hex[65];
            zcl_hex_encode(f->chunk_hashes + (size_t)c * 32u, 32, hex);
            char chunk_path[4200];
            snprintf(chunk_path, sizeof(chunk_path), "%s/cas/sha3/%.2s/%s",
                     store_dir, hex, hex);
            size_t chunk_len = 0;
            uint8_t *chunk = pv_read_file(chunk_path,
                                          VCS_PACKAGE_CHUNK_BYTES,
                                          &chunk_len);
            if (!chunk) {
                close(fd);
                materialized = false;
                break;
            }
            size_t off = 0;
            while (off < chunk_len) {
                ssize_t w = write(fd, chunk + off, chunk_len - off);
                if (w < 0) {
                    if (errno == EINTR)
                        continue;
                    free(chunk);
                    close(fd);
                    materialized = false;
                    break;
                }
                off += (size_t)w;
            }
            free(chunk);
            if (!materialized)
                break;
        }
        if (close(fd) != 0)
            materialized = false;
    }
    if (!materialized) {
        fprintf(stderr, "%s: failed to materialize the package tree\n",
                PV_LOG);
        pv_rm_rf(work);
        vcs_package_recipe_free(&recipe);
        vcs_package_manifest_free(&manifest);
        return 5;
    }

    /* The compile children see the declared (direct) deps' headers; the
     * link child additionally needs the transitive closure's archives and
     * the Landlock read grants that reach them. One closure serves both. */
    struct pv_emit_dep link_deps[PV_EMIT_MAX_DEPS];
    size_t link_dep_count = 0;
    memset(link_deps, 0, sizeof(link_deps));
    if (!pv_expand_link_closure(emit_deps, emit_dep_count, link_deps,
                                &link_dep_count)) {
        fprintf(stderr, "%s: cannot expand the dependency link closure "
                "(unreadable or unparseable installed build-report)\n",
                PV_LOG);
        pv_rm_rf(work);
        vcs_package_recipe_free(&recipe);
        vcs_package_manifest_free(&manifest);
        return 5;
    }

    struct os_sandbox_path_rule rules[10u + PV_EMIT_MAX_DEPS];
    size_t n_rules = pv_child_grants(src_root, build_root, link_deps,
                                     link_dep_count, rules,
                                     sizeof(rules) / sizeof(rules[0]));

    /* Compiler probes (version strings are recorded in the attestation). */
    struct pv_compiler compilers[2] = {
        { .id = "clang", .path = "/usr/bin/clang", .available = false,
          .outcome = VCS_PACKAGE_ATTEST_OUTCOME_UNAVAILABLE },
        { .id = "gcc", .path = VCS_BUILD_COMPILER_V1, .available = false,
          .outcome = VCS_PACKAGE_ATTEST_OUTCOME_UNAVAILABLE },
    };
    for (size_t i = 0; i < 2; i++) {
        const char *vargv[] = { compilers[i].path, "--version", NULL };
        const char *cargv[] = {
            compilers[i].path, "-std=c23", "-fsyntax-only", "-x", "c",
            "/dev/null", NULL,
        };
        struct pv_run pr = pv_run_child(vargv, NULL, NULL, landlock, rules,
                                        n_rules, NULL, 10000);
        struct pv_run capability = pv_run_child(
            cargv, NULL, NULL, false, NULL, 0, NULL, 10000);
        if (pr.launched && pr.exited && pr.exit_code == 0 &&
            pr.stdout_buf[0] && capability.launched && capability.exited &&
            capability.exit_code == 0) {
            compilers[i].available = true;
            size_t vl = strcspn(pr.stdout_buf, "\r\n");
            if (vl >= sizeof(compilers[i].version))
                vl = sizeof(compilers[i].version) - 1;
            for (size_t k = 0; k < vl; k++) {
                unsigned char c = (unsigned char)pr.stdout_buf[k];
                compilers[i].version[k] =
                    (c >= 0x20 && c <= 0x7e) ? (char)c : '?';
            }
            compilers[i].version[vl] = '\0';
        } else {
            snprintf(compilers[i].version, sizeof(compilers[i].version),
                     "unavailable");
        }
    }
    /* Sanitizers need one real runtime execution, not a same-host quorum.
     * Prefer Clang deterministically: GCC ASan can be unavailable when its
     * fixed shadow range collides with the worker process layout. Plain
     * warning-fatal compilation still covers every available compiler. */
    size_t sanitizer_compiler = compilers[0].available ? 0u : 1u;

    struct pv_dep_archives dep_archives;
    memset(&dep_archives, 0, sizeof(dep_archives));
    if (!pv_collect_dep_archives(link_deps, link_dep_count, &dep_archives)) {
        fprintf(stderr, "%s: dependency archive set is invalid\n", PV_LOG);
        pv_rm_rf(work);
        vcs_package_recipe_free(&recipe);
        vcs_package_manifest_free(&manifest);
        return 5;
    }

    /* The build+test matrix. */
    struct vcs_package_attest att;
    memset(&att, 0, sizeof(att));
    att.schema_version = VCS_PACKAGE_ATTEST_VERSION;
    memcpy(att.package_root, package_root, 32);
    memcpy(att.release_id, release_id, 32);
    memcpy(att.recipe_root, recipe_root, 32);
    att.isolation = landlock ? VCS_PACKAGE_ATTEST_ISOLATION_FULL
                             : VCS_PACKAGE_ATTEST_ISOLATION_DEGRADED;
    memcpy(att.verifier_pubkey, verifier_pubkey, 33);

    const bool have_tests = recipe.test_sources.count > 0;
    bool build_ok = true;
    uint8_t build_fail_code = VCS_PACKAGE_ATTEST_DETAIL_COMPILE_ERROR;
    char build_fail_detail[VCS_PACKAGE_ATTEST_DETAIL_MAX + 1u];
    build_fail_detail[0] = '\0';

    char env_tmpdir[4200];
    snprintf(env_tmpdir, sizeof(env_tmpdir), "TMPDIR=%s", build_root);
    /* Pinned locale/clock so neither diagnostics nor __DATE__/__TIME__ can
     * depend on the build host — the same pinning the zbuild unit path and
     * the release profile already apply. */
    const char *const compile_env[] = {
        env_tmpdir, "LANG=C", "TZ=UTC", "SOURCE_DATE_EPOCH=0", NULL,
    };
    char san_asan[96];
    char san_ubsan[96];
    /* detect_leaks=0 is deliberate: LeakSanitizer's stop-the-world needs
     * ptrace + /proc/self access, both denied by the child confinement
     * (seccomp deny-set, Landlock grants) — leak checking is fundamentally
     * incompatible with the sandbox, so ASan runs its memory-error detector
     * only. UBSan is unaffected. */
    snprintf(san_asan, sizeof(san_asan),
             "ASAN_OPTIONS=exitcode=%d:detect_leaks=0", PV_ASAN_EXIT);
    snprintf(san_ubsan, sizeof(san_ubsan),
             "UBSAN_OPTIONS=halt_on_error=1:exitcode=%d:print_stacktrace=1",
             PV_UBSAN_EXIT);
    const char *const san_env[] = { env_tmpdir, san_asan, san_ubsan, NULL };

    const struct os_sandbox_rlimits compile_limits = {
        .as_bytes = PV_COMPILE_AS_BYTES,
        .cpu_seconds = PV_COMPILE_TIMEOUT_MS / 1000 + 5,
        .nproc = PV_COMPILE_NPROC,
        .fsize_bytes = PV_COMPILE_FSIZE_BYTES,
        .nofile = PV_COMPILE_NOFILE,
        .core_bytes = 0,
    };
    const struct os_sandbox_rlimits test_limits = {
        .as_bytes = recipe.maximum_memory_bytes,
        .cpu_seconds = recipe.maximum_test_seconds,
        .nproc = PV_TEST_NPROC,
        .fsize_bytes = PV_TEST_FSIZE_BYTES,
        .nofile = PV_TEST_NOFILE,
        .core_bytes = 0,
    };
    const struct os_sandbox_rlimits san_test_limits = {
        /* ASan's shadow address space makes RLIMIT_AS meaningless — the
         * ONE documented rlimit exception (see the file header). */
        .as_bytes = OS_SANDBOX_RLIMIT_KEEP,
        .cpu_seconds = recipe.maximum_test_seconds,
        .nproc = PV_TEST_NPROC,
        .fsize_bytes = PV_TEST_FSIZE_BYTES,
        .nofile = PV_COMPILE_NOFILE,
        .core_bytes = 0,
    };

    /* Dependency plan (zcl.dep_plan.v1) and the per-TU fast object cache
     * share one preprocess pass and one toolchain capsule: the probes run
     * BEFORE any real compile, under the same confinement; a plan or cache
     * failure fails the whole run closed, before any build output exists. */
    struct pv_plan_ctx pctx;
    memset(&pctx, 0, sizeof(pctx));
    struct vcs_toolchain_capsule_v1 fast_capsule;
    memset(&fast_capsule, 0, sizeof(fast_capsule));
    uint8_t fast_capsule_root[32] = { 0 };
    uint8_t plan_preproc[VCS_PACKAGE_RECIPE_MAX_PATHS_PER_LIST][32];
    memset(plan_preproc, 0, sizeof(plan_preproc));
    bool plan_preproc_valid = false;
    if (plan_path || fast_cache_dir) {
        if (!compilers[1].available) {
            fprintf(stderr, "%s: --plan/--fast-cache require gcc, which is "
                            "unavailable\n", PV_LOG);
            pv_rm_rf(work);
            vcs_package_recipe_free(&recipe);
            vcs_package_manifest_free(&manifest);
            return 5;
        }
        pctx.recipe = &recipe;
        pctx.src_root = src_root;
        pctx.build_root = build_root;
        pctx.deps = emit_deps;
        pctx.dep_count = emit_dep_count;
        pctx.rules = rules;
        pctx.n_rules = n_rules;
        pctx.landlock = landlock;
        pctx.env = compile_env;
        pctx.limits = &compile_limits;
        pctx.warning_fatal = standard_profile;
        if (fast_cache_dir) {
            /* The parent is the cache's only writer (confined children get
             * no grant); canonicalize after creating so the path recorded
             * in diagnostics is absolute. */
            if (!pv_mkdir_p(fast_cache_dir, 0700)) {
                fprintf(stderr, "%s: cannot create --fast-cache dir %s\n",
                        PV_LOG, fast_cache_dir);
                pv_rm_rf(work);
                vcs_package_recipe_free(&recipe);
                vcs_package_manifest_free(&manifest);
                return 5;
            }
            static char fast_cache_resolved[4096];
            if (!realpath(fast_cache_dir, fast_cache_resolved)) {
                fprintf(stderr, "%s: cannot resolve --fast-cache dir %s\n",
                        PV_LOG, fast_cache_dir);
                pv_rm_rf(work);
                vcs_package_recipe_free(&recipe);
                vcs_package_manifest_free(&manifest);
                return 5;
            }
            fast_cache_dir = fast_cache_resolved;
            if (!vcs_toolchain_capsule_v1_capture_gcc(&fast_capsule) ||
                !vcs_toolchain_capsule_v1_root(&fast_capsule,
                                               fast_capsule_root)) {
                fprintf(stderr, "%s: --fast-cache: toolchain capsule "
                                "capture failed\n", PV_LOG);
                pv_rm_rf(work);
                vcs_package_recipe_free(&recipe);
                vcs_package_manifest_free(&manifest);
                return 5;
            }
        }
        if (plan_path &&
            !pv_emit_dep_plan(plan_path, release.name, package_root,
                              recipe_root, emit_lock_root,
                              standard_profile ? "standard" : "quick",
                              compilers[1].id, compilers[1].path,
                              compilers[1].version, &pctx, plan_preproc)) {
            fprintf(stderr, "%s: dependency plan failed: %s\n", PV_LOG,
                    pctx.error);
            pv_rm_rf(work);
            vcs_package_recipe_free(&recipe);
            vcs_package_manifest_free(&manifest);
            return 5;
        }
        plan_preproc_valid = plan_path != NULL;
    }

    for (size_t ci = 0; ci < 2 && build_ok; ci++) {
        if (!compilers[ci].available)
            continue;
        const char *cc = compilers[ci].path;
        const char *cc_id = compilers[ci].id;
        bool cc_ok = true;
        for (int variant = 0; variant < 2 && cc_ok; variant++) {
            const bool sanitize = variant == 1;
            /* Sanitizer binaries are only needed when tests will run. */
            if (sanitize &&
                (!have_tests || ci != sanitizer_compiler))
                continue;
            char fail_prefix[32];
            snprintf(fail_prefix, sizeof(fail_prefix), "%s%s", cc_id,
                     sanitize ? "+san" : "");
            const size_t total_sources =
                recipe.sources.count +
                (have_tests ? recipe.test_sources.count : 0);
            for (size_t si = 0; si < total_sources && cc_ok; si++) {
                const char *rel = si < recipe.sources.count
                    ? recipe.sources.items[si]
                    : recipe.test_sources
                          .items[si - recipe.sources.count];
                char src_file[4200];
                char obj_file[4200];
                snprintf(src_file, sizeof(src_file), "%s/%s", src_root, rel);
                snprintf(obj_file, sizeof(obj_file),
                         "%s/%s_%d_%zu.o", build_root, cc_id, variant, si);
                struct pv_compile_args args;
                memset(&args, 0, sizeof(args));
                pv_compile_argv(&args, cc, sanitize, standard_profile,
                                &recipe, src_root,
                                emit_deps, emit_dep_count, src_file,
                                obj_file);
                struct pv_run pr;
                memset(&pr, 0, sizeof(pr));
                /* Per-TU object cache: only the plain gcc variant of a
                 * recipe source is eligible (the plan's preprocess probes
                 * use exactly that argv; clang and sanitizer objects are
                 * always rebuilt). Compare the attestation id, not the
                 * executable path — the secure lane invokes the compiler
                 * by its absolute path (VCS_BUILD_COMPILER_V1). */
                const bool fast_eligible = fast_cache_dir &&
                    strcmp(cc_id, "gcc") == 0 && !sanitize &&
                    si < recipe.sources.count;
                bool from_cache = false;
                uint8_t fast_preproc[32] = { 0 };
                uint8_t fast_key[32] = { 0 };
                if (fast_eligible) {
                    char ferr[240];
                    if (plan_preproc_valid)
                        memcpy(fast_preproc, plan_preproc[si], 32);
                    else if (!pv_fast_preproc_sha3(&pctx, &args, si,
                                                   src_file, fast_preproc,
                                                   ferr, sizeof(ferr))) {
                        fprintf(stderr, "%s: fast cache preprocess probe "
                                        "failed: %s\n", PV_LOG, ferr);
                        pv_rm_rf(work);
                        vcs_package_recipe_free(&recipe);
                        vcs_package_manifest_free(&manifest);
                        return 5;
                    }
                    if (!pv_fastobj_key(&pctx,
                                        standard_profile ? "standard"
                                                         : "quick",
                                        fast_capsule.target,
                                        fast_capsule_root, &args,
                                        fast_preproc, fast_key)) {
                        fprintf(stderr, "%s: fast cache key derivation "
                                        "failed\n", PV_LOG);
                        pv_rm_rf(work);
                        vcs_package_recipe_free(&recipe);
                        vcs_package_manifest_free(&manifest);
                        return 5;
                    }
                    int hit = pv_fast_cache_lookup(fast_cache_dir,
                                                   fast_key, obj_file, ferr,
                                                   sizeof(ferr));
                    if (hit < 0) {
                        fprintf(stderr, "%s: %s\n", PV_LOG, ferr);
                        pv_rm_rf(work);
                        vcs_package_recipe_free(&recipe);
                        vcs_package_manifest_free(&manifest);
                        return 5;
                    }
                    from_cache = hit == 1;
                }
                if (from_cache) {
                    /* A verified hit IS a completed successful compile:
                     * the object bytes are already materialized at
                     * obj_file and re-verified against the sidecar. */
                    pr.launched = true;
                    pr.exited = true;
                    pr.exit_code = 0;
                } else {
                    pr = pv_run_child(
                        args.argv, build_root, &compile_limits, landlock,
                        rules, n_rules, compile_env, PV_COMPILE_TIMEOUT_MS);
                }
                if (!pr.launched || pr.sandbox_fail) {
                    fprintf(stderr,
                            "%s: internal: compile child failed to launch "
                            "or arm its sandbox (%s)\n", PV_LOG,
                            pr.stderr_buf);
                    pv_rm_rf(work);
                    vcs_package_recipe_free(&recipe);
                    vcs_package_manifest_free(&manifest);
                    return 5;
                }
                if (pr.timed_out) {
                    cc_ok = false;
                    build_fail_code =
                        VCS_PACKAGE_ATTEST_DETAIL_COMPILE_TIMEOUT;
                    snprintf(build_fail_detail, sizeof(build_fail_detail),
                             "%s: compile timed out: %s", fail_prefix, rel);
                } else if (!pr.exited || pr.exit_code != 0) {
                    cc_ok = false;
                    build_fail_code =
                        VCS_PACKAGE_ATTEST_DETAIL_COMPILE_ERROR;
                    pv_detail_from_stderr(fail_prefix, pr.stderr_buf,
                                          build_fail_detail,
                                          sizeof(build_fail_detail));
                } else if (fast_eligible && !from_cache) {
                    char ferr[240];
                    if (!pv_fast_cache_store(
                            &pctx, fast_cache_dir, fast_key,
                            standard_profile ? "standard" : "quick",
                            fast_capsule.target, fast_capsule_root, &args,
                            fast_preproc, rel, package_root, recipe_root,
                            emit_lock_root, obj_file, ferr, sizeof(ferr))) {
                        fprintf(stderr, "%s: %s\n", PV_LOG, ferr);
                        pv_rm_rf(work);
                        vcs_package_recipe_free(&recipe);
                        vcs_package_manifest_free(&manifest);
                        return 5;
                    }
                }
            }
            /* Link the test binary (plain and sanitizer variants). Object
             * names are deterministic — regenerated, never stored. */
            if (cc_ok && have_tests) {
                char bin_file[4200];
                snprintf(bin_file, sizeof(bin_file), "%s/%s_%d_test",
                         build_root, cc_id, variant);
                const char *largv[560];
                char lobjs[512][96];
                size_t ln = 0;
                largv[ln++] = cc;
                if (sanitize)
                    largv[ln++] = "-fsanitize=address,undefined";
                if (sanitize)
                    largv[ln++] = "-no-pie";
                for (size_t o = 0; o < total_sources &&
                                   o < sizeof(lobjs) / sizeof(lobjs[0]);
                     o++) {
                    /* cwd is build_root: basenames resolve there. */
                    snprintf(lobjs[o], sizeof(lobjs[o]), "%s_%d_%zu.o", cc_id,
                             variant, o);
                    largv[ln++] = lobjs[o];
                }
                largv[ln++] = "-o";
                largv[ln++] = bin_file;
                /* Locked dependency archives come after the objects that
                 * reference them. The transitive closure is wrapped in a
                 * linker group: within a group the linker rescans until no
                 * new symbol resolves, so provider-before-dependent order
                 * inside the closure cannot break the link. */
                if (dep_archives.count &&
                    ln + 4u < sizeof(largv) / sizeof(largv[0]))
                    largv[ln++] = "-Wl,--start-group";
                for (size_t da = 0; da < dep_archives.count &&
                                    ln + 8u < sizeof(largv) / sizeof(largv[0]);
                     da++)
                    largv[ln++] = dep_archives.path[da];
                if (dep_archives.count &&
                    ln + 4u < sizeof(largv) / sizeof(largv[0]))
                    largv[ln++] = "-Wl,--end-group";
                for (size_t li = 0; li < recipe.library_count; li++) {
                    if (recipe.libraries[li] == VCS_PACKAGE_RECIPE_LIB_LIBM)
                        largv[ln++] = "-lm";
                    else if (recipe.libraries[li] ==
                             VCS_PACKAGE_RECIPE_LIB_PTHREAD)
                        largv[ln++] = "-lpthread";
                }
                largv[ln] = NULL;
                struct pv_run pr = pv_run_child(
                    largv, build_root, &compile_limits, landlock, rules,
                    n_rules, compile_env, PV_LINK_TIMEOUT_MS);
                if (!pr.launched || pr.sandbox_fail) {
                    fprintf(stderr,
                            "%s: internal: link child failed to launch or "
                            "arm its sandbox (%s)\n", PV_LOG, pr.stderr_buf);
                    pv_rm_rf(work);
                    vcs_package_recipe_free(&recipe);
                    vcs_package_manifest_free(&manifest);
                    return 5;
                }
                if (pr.timed_out) {
                    cc_ok = false;
                    build_fail_code =
                        VCS_PACKAGE_ATTEST_DETAIL_COMPILE_TIMEOUT;
                    snprintf(build_fail_detail, sizeof(build_fail_detail),
                             "%s: link timed out", fail_prefix);
                } else if (!pr.exited || pr.exit_code != 0) {
                    cc_ok = false;
                    build_fail_code = VCS_PACKAGE_ATTEST_DETAIL_LINK_ERROR;
                    pv_detail_from_stderr(fail_prefix, pr.stderr_buf,
                                          build_fail_detail,
                                          sizeof(build_fail_detail));
                }
            }
            if (!cc_ok) {
                compilers[ci].outcome = VCS_PACKAGE_ATTEST_OUTCOME_FAIL;
                build_ok = false;
                break;
            }
        }
        if (build_ok && compilers[ci].available)
            compilers[ci].outcome = VCS_PACKAGE_ATTEST_OUTCOME_PASS;
    }

    /* Test runs (only when every compiler built). */
    bool test_ok = true;
    bool test_ran = false;
    uint32_t test_exit = 0;
    uint8_t test_fail_code = VCS_PACKAGE_ATTEST_DETAIL_NONE;
    char test_fail_detail[VCS_PACKAGE_ATTEST_DETAIL_MAX + 1u];
    test_fail_detail[0] = '\0';
    bool sanitizer_clean = true;
    uint8_t sanitizer_fail_code = VCS_PACKAGE_ATTEST_DETAIL_NONE;
    char sanitizer_fail_detail[VCS_PACKAGE_ATTEST_DETAIL_MAX + 1u];
    sanitizer_fail_detail[0] = '\0';

    if (build_ok && have_tests) {
        for (size_t ci = 0; ci < 2; ci++) {
            if (!compilers[ci].available)
                continue;
            const char *cc = compilers[ci].id;
            /* Plain run: the resource-bound verdict. */
            char bin_file[4200];
            snprintf(bin_file, sizeof(bin_file), "%s/%s_0_test", build_root,
                     cc);
            struct pv_run pr = pv_run_child(
                (const char *const[]){ bin_file, NULL }, build_root,
                &test_limits, landlock, rules, n_rules, compile_env,
                (int)recipe.maximum_test_seconds * 1000 + 5000);
            if (!pr.launched || pr.sandbox_fail) {
                fprintf(stderr,
                        "%s: internal: test child failed to launch or arm "
                        "its sandbox\n", PV_LOG);
                pv_rm_rf(work);
                vcs_package_recipe_free(&recipe);
                vcs_package_manifest_free(&manifest);
                return 5;
            }
            test_ran = true;
            if (pr.timed_out) {
                test_ok = false;
                test_fail_code = VCS_PACKAGE_ATTEST_DETAIL_TEST_TIMEOUT;
                snprintf(test_fail_detail, sizeof(test_fail_detail),
                         "%s: test exceeded %u s", cc,
                         recipe.maximum_test_seconds);
            } else if (pr.exited) {
                test_exit = (uint32_t)pr.exit_code;
                if (pr.exit_code != recipe.expected_test_exit_code) {
                    test_ok = false;
                    test_fail_code =
                        VCS_PACKAGE_ATTEST_DETAIL_TEST_EXIT_MISMATCH;
                    /* Carry the failing run's own last line: "exit 1" alone
                     * is undiagnosable from the operator's side of the
                     * sandbox. Test failures conventionally go to stderr;
                     * fall back to stdout. One line, printable ASCII. */
                    const char *s = pr.stderr_buf;
                    size_t sl = pr.stderr_len;
                    if (!sl) {
                        s = pr.stdout_buf;
                        sl = pr.stdout_len;
                    }
                    char tail[121];
                    size_t begin = sl;
                    while (begin > 0 && s[begin - 1] != '\n' &&
                           sl - begin < sizeof(tail) - 1)
                        begin--;
                    if (begin > 0 && begin == sl)
                        begin--; /* no newline: keep the tail, not the head */
                    size_t ti = 0;
                    for (size_t k = begin; k < sl && ti < sizeof(tail) - 1;
                         k++) {
                        unsigned char c = (unsigned char)s[k];
                        tail[ti++] = (c >= 0x20 && c <= 0x7e) ? (char)c
                                                              : '?';
                    }
                    while (ti && tail[ti - 1] == '\n')
                        ti--;
                    tail[ti] = '\0';
                    snprintf(test_fail_detail, sizeof(test_fail_detail),
                             "%s: exit %d, expected %u%s%s", cc, pr.exit_code,
                             recipe.expected_test_exit_code,
                             ti ? ": " : "", tail);
                }
            } else {
                test_ok = false;
                test_fail_code = VCS_PACKAGE_ATTEST_DETAIL_TEST_SIGNAL;
                snprintf(test_fail_detail, sizeof(test_fail_detail),
                         "%s: killed by signal %d", cc, pr.term_signal);
            }
            /* Sanitizer run: one deterministic real ASan+UBSan execution. */
            if (ci != sanitizer_compiler)
                continue;
            char san_bin[4200];
            snprintf(san_bin, sizeof(san_bin), "%s/%s_1_test", build_root,
                     cc);
            const char *const sanitizer_argv[] = {
                "setarch", "x86_64", "-R", san_bin, NULL,
            };
            struct pv_run sr = pv_run_child(
                sanitizer_argv, build_root,
                &san_test_limits, landlock, rules, n_rules, san_env,
                (int)recipe.maximum_test_seconds * 1000 + 5000);
            if (!sr.launched || sr.sandbox_fail) {
                fprintf(stderr,
                        "%s: internal: sanitizer child failed to launch or "
                        "arm its sandbox\n", PV_LOG);
                pv_rm_rf(work);
                vcs_package_recipe_free(&recipe);
                vcs_package_manifest_free(&manifest);
                return 5;
            }
            /* A sanitizer run failure is a FINDING only when the run died
             * by the sanitizer's own marker exit code (a real report — the
             * text is captured into the detail). Any other death — killed
             * by the seccomp deny-set, the wall-clock deadline, a wrong
             * exit code — mirrors the (identically confined) plain run or
             * host load and says nothing about UB: the diagnostic is then
             * UNAVAILABLE, never a finding. Findings are recorded only
             * when every plain run passed: the closed grammar allows a
             * findings outcome only in the sanitizer-fail class. Precedence
             * across compilers: findings > unavailable > pass. */
            bool san_failed =
                sr.timed_out || !sr.exited ||
                sr.exit_code != recipe.expected_test_exit_code;
            if (san_failed) {
                /* A marker exit code alone is NOT proof of a report: the
                 * runtimes also abort through the same exit path when ASan
                 * cannot INITIALIZE (a fixed-shadow collision under host
                 * memory pressure prints "Shadow memory range interleaves
                 * ... ASan cannot proceed correctly. ABORTING."). A finding
                 * requires the report text itself (ASan "SUMMARY:" / UBSan
                 * "runtime error:"); anything else is environmental and
                 * makes the diagnostic UNAVAILABLE, never dirty. */
                bool reported =
                    strstr(sr.stderr_buf, "SUMMARY:") != NULL ||
                    strstr(sr.stderr_buf, "runtime error:") != NULL;
                bool finding = false;
                char sprefix[40];
                snprintf(sprefix, sizeof(sprefix), "%s+san", cc);
                if (test_ok && reported && sr.exited &&
                    sr.exit_code == PV_ASAN_EXIT) {
                    att.sanitizers[0].outcome =
                        VCS_PACKAGE_ATTEST_OUTCOME_FAIL;
                    sanitizer_fail_code =
                        VCS_PACKAGE_ATTEST_DETAIL_ASAN_FINDINGS;
                    finding = true;
                } else if (test_ok && reported && sr.exited &&
                           sr.exit_code == PV_UBSAN_EXIT) {
                    att.sanitizers[1].outcome =
                        VCS_PACKAGE_ATTEST_OUTCOME_FAIL;
                    sanitizer_fail_code =
                        VCS_PACKAGE_ATTEST_DETAIL_UBSAN_FINDINGS;
                    finding = true;
                }
                if (finding) {
                    sanitizer_clean = false;
                    pv_san_detail_from_stderr(sprefix, sr.stderr_buf,
                                              sanitizer_fail_detail,
                                              sizeof(sanitizer_fail_detail));
                    break;   /* a finding is definitive */
                }
                if (att.sanitizers[0].outcome !=
                        VCS_PACKAGE_ATTEST_OUTCOME_FAIL &&
                    att.sanitizers[1].outcome !=
                        VCS_PACKAGE_ATTEST_OUTCOME_FAIL) {
                    att.sanitizers[0].outcome =
                        VCS_PACKAGE_ATTEST_OUTCOME_UNAVAILABLE;
                    att.sanitizers[1].outcome =
                        VCS_PACKAGE_ATTEST_OUTCOME_UNAVAILABLE;
                    pv_san_detail_from_stderr(
                        sprefix, sr.stderr_buf, sanitizer_fail_detail,
                        sizeof(sanitizer_fail_detail));
                }
                continue;   /* an unavailable diagnostic decides nothing */
            }
            /* Clean run: leave the outcome as-is (pass by default; a
             * previous compiler's unavailable is not upgraded — the
             * diagnostic is only as strong as its weakest run). */
        }
    }

    /* Assemble the verdict. */
    for (size_t i = 0; i < 2; i++) {
        snprintf(att.compilers[i].id, sizeof(att.compilers[i].id), "%s",
                 compilers[i].id);
        snprintf(att.compilers[i].version,
                 sizeof(att.compilers[i].version), "%s",
                 compilers[i].version);
        att.compilers[i].outcome = compilers[i].outcome;
    }
    att.compiler_count = 2;
    if (have_tests) {
        snprintf(att.sanitizers[0].name,
                 sizeof(att.sanitizers[0].name), "asan");
        snprintf(att.sanitizers[1].name,
                 sizeof(att.sanitizers[1].name), "ubsan");
        att.sanitizer_count = 2;
        if (!build_ok) {
            att.sanitizers[0].outcome =
                VCS_PACKAGE_ATTEST_OUTCOME_UNAVAILABLE;
            att.sanitizers[1].outcome =
                VCS_PACKAGE_ATTEST_OUTCOME_UNAVAILABLE;
        }
    }
    att.test_ran = test_ran;
    att.test_exit_code = test_ran ? test_exit : 0;

    if (!build_ok) {
        att.result_class = VCS_PACKAGE_ATTEST_RESULT_BUILD_FAIL;
        att.detail_code = build_fail_code;
        snprintf(att.detail, sizeof(att.detail), "%s", build_fail_detail);
    } else if (have_tests && !test_ok) {
        att.result_class = VCS_PACKAGE_ATTEST_RESULT_TEST_FAIL;
        att.detail_code = test_fail_code;
        snprintf(att.detail, sizeof(att.detail), "%s", test_fail_detail);
    } else if (have_tests && !sanitizer_clean) {
        att.result_class = VCS_PACKAGE_ATTEST_RESULT_SANITIZER_FAIL;
        att.detail_code = sanitizer_fail_code;
        snprintf(att.detail, sizeof(att.detail), "%s",
                 sanitizer_fail_detail);
    } else if (have_tests) {
        att.result_class = VCS_PACKAGE_ATTEST_RESULT_TEST_PASS;
    } else {
        att.result_class = VCS_PACKAGE_ATTEST_RESULT_BUILD_PASS;
    }

    /* No compiler at all: there is no honest verdict to sign. */
    if (!compilers[0].available && !compilers[1].available) {
        fprintf(stderr,
                "%s: neither gcc nor clang is available — no attestation "
                "signed\n", PV_LOG);
        pv_rm_rf(work);
        vcs_package_recipe_free(&recipe);
        vcs_package_manifest_free(&manifest);
        return 5;
    }

    /* The standard-profile refusal guards the EVIDENCE track: a candidate
     * standard run that composes admission evidence (the build fabric's
     * candidate builds, the factory's standard-profile rebuild — neither
     * passes --allow-testless-standard) must show declared tests and clean
     * ASan+UBSan runs before package evidence may carry the standard
     * profile's name. Every candidate run emits (candidate_shape requires
     * --emit and refuses --key), so the exemption is keyed on the explicit
     * opt-in flag instead: the reproduce track (package lifecycle
     * reproduce, cross-machine reproduce) rebuilds an ALREADY-accepted
     * package whose honesty bar is two distinct build events agreeing on
     * every committed output (vcs_package_reproduce_scan), not the
     * evidence-track test policy, and its receipt still records the
     * observed facts honestly (test_ran=false, and the flags string's
     * sanitizer segment names the observed outcome — not-run / findings /
     * unavailable / clean — composed in the emit path below). */
    bool standard_sanitizers_passed = have_tests && test_ran && test_ok &&
        att.sanitizer_count == 2u &&
        att.sanitizers[0].outcome == VCS_PACKAGE_ATTEST_OUTCOME_PASS &&
        att.sanitizers[1].outcome == VCS_PACKAGE_ATTEST_OUTCOME_PASS;
    if (candidate_mode && standard_profile && !allow_testless_standard &&
        !standard_sanitizers_passed) {
        /* Name the real cause: a build or test failure leaves the sanitizer
         * detail empty, and printing only that field misdirects the
         * operator toward a sanitizer problem that never ran. */
        const char *cause = !build_ok ? build_fail_detail
            : (have_tests && !test_ok) ? test_fail_detail
            : sanitizer_fail_detail;
        if (!cause[0])
            cause = have_tests ? "sanitizer diagnostic unavailable"
                               : "recipe declares no test sources";
        fprintf(stdout,
                "zbuild-package-standard-refused=1 asan=%u ubsan=%u "
                "detail=%.120s\n", att.sanitizers[0].outcome,
                att.sanitizers[1].outcome, cause);
        fprintf(stderr,
                "%s: standard profile requires declared tests and clean "
                "ASan+UBSan runs; package evidence refused "
                "(asan=%u ubsan=%u detail=%s)\n", PV_LOG,
                att.sanitizers[0].outcome, att.sanitizers[1].outcome, cause);
        pv_rm_rf(work);
        vcs_package_recipe_free(&recipe);
        vcs_package_manifest_free(&manifest);
        return 6;
    }

    /* ── emit mode: archive, install-stage, receipt (nothing is signed) ── */
    if (emit_dir) {
        struct vcs_package_build_receipt rec;
        vcs_package_build_receipt_init(&rec);
        memcpy(rec.package_root, package_root, 32);
        memcpy(rec.recipe_root, recipe_root, 32);
        memcpy(rec.lock_root, emit_lock_root, 32);
        for (size_t i = 0; i < emit_dep_count; i++) {
            enum vcs_package_build_error de =
                vcs_package_build_add_dep(&rec, emit_deps[i].root);
            if (de != VCS_PACKAGE_BUILD_OK) {
                fprintf(stderr, "%s: --dep set rejected: %s\n", PV_LOG,
                        vcs_package_build_error_string(de));
                pv_rm_rf(work);
                vcs_package_recipe_free(&recipe);
                vcs_package_manifest_free(&manifest);
                return 2;
            }
        }
        /* Deterministic compiler choice: gcc when present, else clang. The
         * verdict above already required BOTH available compilers to pass. */
        const size_t pick = compilers[1].available ? 1u : 0u;
        snprintf(rec.compiler_id, sizeof(rec.compiler_id), "%s",
                 compilers[pick].id);
        snprintf(rec.compiler_version, sizeof(rec.compiler_version), "%s",
                 compilers[pick].version);
        if (standard_profile) {
            /* The sanitizer segment records the OBSERVED outcome, never the
             * profile name. On the evidence track it always reads "clean"
             * (the refusal above fired unless both outcomes are PASS); the
             * reproduce track (--allow-testless-standard) can also reach
             * "not-run" (testless recipe — the sanitizer stage never
             * executed), "findings" (a real ASan/UBSan report: the receipt
             * remains installable build evidence, exactly as quick emit
             * always behaved, but it may not claim cleanliness), or
             * "unavailable" (the diagnostic could not run). Precedence
             * mirrors the attestation lane: findings > clean > unavailable.
             */
            const char *san_seg = "unavailable";
            if (!have_tests)
                san_seg = "not-run";
            else if (att.sanitizers[0].outcome ==
                         VCS_PACKAGE_ATTEST_OUTCOME_FAIL ||
                     att.sanitizers[1].outcome ==
                         VCS_PACKAGE_ATTEST_OUTCOME_FAIL)
                san_seg = "findings";
            else if (att.sanitizers[0].outcome ==
                         VCS_PACKAGE_ATTEST_OUTCOME_PASS &&
                     att.sanitizers[1].outcome ==
                         VCS_PACKAGE_ATTEST_OUTCOME_PASS)
                san_seg = "clean";
            snprintf(rec.flags, sizeof(rec.flags),
                     "%s;asan,ubsan=%s;sanitizer_pie=off;sanitizer_aslr=off",
                     ZCL_C23_COMMONS_BUILD_FLAGS_STANDARD_BASE_V2, san_seg);
        } else {
            snprintf(rec.flags, sizeof(rec.flags), "%s",
                     ZCL_C23_COMMONS_BUILD_FLAGS_QUICK_V2);
        }
        /* The receipt names its toolchain exactly: schema v2 carries the
         * toolchain capsule root. The capsule capture is gcc-only today,
         * so a clang-picked receipt honestly stays v1; on the gcc path a
         * capture failure fails closed — no unpinned receipt. The capture
         * is cached in-process, so this is cheap even when --fast-cache
         * already captured it. */
        if (pick == 1u) {
            struct vcs_toolchain_capsule_v1 rec_capsule;
            uint8_t rec_capsule_root[32];
            memset(&rec_capsule, 0, sizeof(rec_capsule));
            if (!vcs_toolchain_capsule_v1_capture_gcc(&rec_capsule) ||
                !vcs_toolchain_capsule_v1_root(&rec_capsule,
                                               rec_capsule_root) ||
                vcs_package_build_set_toolchain_capsule(
                    &rec, rec_capsule_root) != VCS_PACKAGE_BUILD_OK) {
                fprintf(stderr, "%s: toolchain capsule capture failed — "
                                "refusing to emit an unpinned receipt\n",
                        PV_LOG);
                pv_rm_rf(work);
                vcs_package_recipe_free(&recipe);
                vcs_package_manifest_free(&manifest);
                return 5;
            }
        }
        rec.isolation = landlock
                            ? (uint8_t)VCS_PACKAGE_BUILD_ISOLATION_FULL
                            : (uint8_t)VCS_PACKAGE_BUILD_ISOLATION_DEGRADED;
        rec.test_ran = have_tests && test_ran;
        rec.test_exit_code = rec.test_ran ? test_exit : 0u;
        if (!build_ok)
            rec.result_class = (uint8_t)VCS_PACKAGE_BUILD_RESULT_BUILD_FAIL;
        else if (have_tests && !test_ok)
            rec.result_class = (uint8_t)VCS_PACKAGE_BUILD_RESULT_TEST_FAIL;
        else if (have_tests)
            rec.result_class = (uint8_t)VCS_PACKAGE_BUILD_RESULT_TEST_PASS;
        else
            rec.result_class = (uint8_t)VCS_PACKAGE_BUILD_RESULT_BUILD_PASS;
        /* A sanitizer finding is not a build/test verdict in emit mode; the
         * attestation lane owns that diagnostic. The receipt records the
         * build+test verdict only, so a clean test that trips ASan still
         * installs — exactly as the attestation quorum, not the installer,
         * is the place that judges sanitizer cleanliness. The evidence
         * track failed closed above unless both ASan and UBSan were clean;
         * the reproduce track (--allow-testless-standard) instead records
         * the observed outcome in the flags string composed above, so a
         * finding installs but can never masquerade as "clean". */

        bool emitted = true;
        if (vcs_package_build_installable(&rec)) {
            /* Archive the recipe's NON-TEST objects. Test objects hold
             * main() and are never part of an installed library. */
            char pkg_short[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
            const char *slash = strchr(release.name, '/');
            snprintf(pkg_short, sizeof(pkg_short), "%s",
                     slash ? slash + 1 : release.name);
            char archive_name[VCS_PACKAGE_RELEASE_NAME_MAX + 8u];
            snprintf(archive_name, sizeof(archive_name), "lib%s.a", pkg_short);
            const char *aargv[8u + 512u];
            char aobjs[512][96];
            size_t an = 0;
            aargv[an++] = "ar";
            /* D = explicit deterministic mode (zeroed uid/gid/mtime): never
             * rely on the toolchain default for a receipt-bound artifact. */
            aargv[an++] = "rcsD";
            aargv[an++] = archive_name;
            for (size_t o = 0; o < recipe.sources.count &&
                               o < sizeof(aobjs) / sizeof(aobjs[0]);
                 o++) {
                snprintf(aobjs[o], sizeof(aobjs[o]), "%s_0_%zu.o",
                         compilers[pick].id, o);
                aargv[an++] = aobjs[o];
            }
            aargv[an] = NULL;
            struct pv_run ar = pv_run_child(aargv, build_root, &compile_limits,
                                            landlock, rules, n_rules,
                                            compile_env, PV_LINK_TIMEOUT_MS);
            if (!ar.launched || ar.sandbox_fail || ar.timed_out ||
                !ar.exited || ar.exit_code != 0) {
                fprintf(stderr,
                        "%s: `ar rcsD %s` failed (%s) — no artifact emitted\n",
                        PV_LOG, archive_name,
                        ar.timed_out ? "timed out" : ar.stderr_buf);
                emitted = false;
            }
            char src_archive[4300];
            char dst_archive[4400];
            char rel_archive[VCS_PACKAGE_BUILD_PATH_MAX + 1u];
            snprintf(src_archive, sizeof(src_archive), "%s/%s", build_root,
                     archive_name);
            snprintf(rel_archive, sizeof(rel_archive), "lib/%s", archive_name);
            snprintf(dst_archive, sizeof(dst_archive), "%s/%s", emit_dir,
                     rel_archive);
            uint8_t h[32];
            uint64_t nbytes = 0;
            if (emitted &&
                (!pv_copy_file(src_archive, dst_archive, 0644) ||
                 !pv_sha3_file(dst_archive, h, &nbytes) ||
                 vcs_package_build_add_output(&rec, rel_archive, h, nbytes) !=
                     VCS_PACKAGE_BUILD_OK)) {
                fprintf(stderr, "%s: cannot emit %s\n", PV_LOG, dst_archive);
                emitted = false;
            }
            for (size_t i = 0;
                 emitted && i < recipe.public_headers.count; i++) {
                const char *hdr = recipe.public_headers.items[i];
                char rel[VCS_PACKAGE_BUILD_PATH_MAX + 1u];
                pv_header_install_path(&recipe, hdr, rel, sizeof(rel));
                char src_hdr[4300];
                char dst_hdr[4400];
                snprintf(src_hdr, sizeof(src_hdr), "%s/%s", src_root, hdr);
                snprintf(dst_hdr, sizeof(dst_hdr), "%s/%s", emit_dir, rel);
                uint8_t hh[32];
                uint64_t hb = 0;
                if (!pv_copy_file(src_hdr, dst_hdr, 0644) ||
                    !pv_sha3_file(dst_hdr, hh, &hb) ||
                    vcs_package_build_add_output(&rec, rel, hh, hb) !=
                        VCS_PACKAGE_BUILD_OK) {
                    fprintf(stderr, "%s: cannot emit %s\n", PV_LOG, dst_hdr);
                    emitted = false;
                }
            }
            if (!emitted) {
                /* An emit failure is an INTERNAL failure, never a silent
                 * "build failed" verdict: the build genuinely passed. */
                pv_rm_rf(work);
                vcs_package_recipe_free(&recipe);
                vcs_package_manifest_free(&manifest);
                return 5;
            }
        }

        uint8_t *rwire2 = NULL;
        size_t rwire2_len = 0;
        enum vcs_package_build_error be =
            vcs_package_build_serialize(&rec, &rwire2, &rwire2_len);
        char report_path[4400];
        snprintf(report_path, sizeof(report_path), "%s/build-report", emit_dir);
        bool wrote = be == VCS_PACKAGE_BUILD_OK && pv_mkdir_p(emit_dir, 0700) &&
                     pv_atomic_write(report_path, rwire2, rwire2_len);
        free(rwire2);
        if (!wrote) {
            fprintf(stderr, "%s: cannot write %s (%s)\n", PV_LOG, report_path,
                    vcs_package_build_error_string(be));
            pv_rm_rf(work);
            vcs_package_recipe_free(&recipe);
            vcs_package_manifest_free(&manifest);
            return 5;
        }
        if (!pv_rm_rf(work))
            fprintf(stderr, "%s: WARNING: temp tree %s not fully removed\n",
                    PV_LOG, work);
        /* Third-party bit-identical reproduction: compare THIS build's
         * receipt against a reference build-report (the publisher's or
         * another verifier's). MATCH is printed on stdout; a divergence is
         * a loud stderr MISMATCH naming the first diverging rule, and the
         * exit code says so (6) — reproduction failure is a verdict, not
         * an internal error. */
        if (reproduce_path) {
            size_t ref_len = 0;
            uint8_t *ref_wire = pv_read_file(reproduce_path,
                                             VCS_PACKAGE_BUILD_MAX_WIRE_BYTES,
                                             &ref_len);
            if (!ref_wire) {
                fprintf(stderr,
                        "%s: REPRODUCTION UNREADABLE: cannot read the "
                        "reference build receipt %s\n", PV_LOG,
                        reproduce_path);
                vcs_package_recipe_free(&recipe);
                vcs_package_manifest_free(&manifest);
                return 3;
            }
            struct vcs_package_build_receipt ref;
            enum vcs_package_build_error rerr =
                vcs_package_build_parse(ref_wire, ref_len, &ref);
            free(ref_wire);
            if (rerr != VCS_PACKAGE_BUILD_OK) {
                fprintf(stderr,
                        "%s: REPRODUCTION UNREADABLE: %s is not a canonical "
                        "build receipt (%s)\n", PV_LOG, reproduce_path,
                        vcs_package_build_error_string(rerr));
                vcs_package_recipe_free(&recipe);
                vcs_package_manifest_free(&manifest);
                return 3;
            }
            struct vcs_reproduce_verdict verdict;
            vcs_package_reproduce_compare(&ref, &rec, &verdict);
            if (!verdict.reproduced) {
                fprintf(stderr,
                        "%s: REPRODUCTION MISMATCH (%s): %s — this build "
                        "does NOT reproduce %s byte-for-byte\n", PV_LOG,
                        vcs_reproduce_rule_string(
                            (enum vcs_reproduce_rule)verdict.rule),
                        verdict.detail, reproduce_path);
                vcs_package_recipe_free(&recipe);
                vcs_package_manifest_free(&manifest);
                return 6;
            }
            printf("reproduction=MATCH outputs=%zu reference=%s\n",
                   rec.output_count, reproduce_path);
        }
        printf("emit=%s result=%s outputs=%zu isolation=%s\n", emit_dir,
               vcs_package_build_result_string(
                   (enum vcs_package_build_result)rec.result_class),
               rec.output_count,
                   vcs_package_build_isolation_string(
                   (enum vcs_package_build_isolation)rec.isolation));
        if (!build_ok)
            printf("build-failure-detail=%s\n",
                   build_fail_detail[0] ? build_fail_detail : "unclassified");
        if (build_ok && !test_ok)
            printf("test-failure-detail=%s\n",
                   test_fail_detail[0] ? test_fail_detail : "unclassified");
        if (candidate_mode) {
            uint64_t source_bytes = 0, output_bytes = 0;
            for (size_t i = 0; i < manifest.count; i++)
                source_bytes += manifest.files[i].size;
            for (size_t i = 0; i < rec.output_count; i++)
                output_bytes += rec.outputs[i].bytes;
            printf("zbuild-package-perf=v1 processes=%llu "
                   "compiler_processes=%llu test_processes=%llu "
                   "other_processes=%llu child_wall_us=%llu "
                   "child_cpu_us=%llu "
                   "compiler_wall_us=%llu test_wall_us=%llu "
                   "source_bytes=%llu output_bytes=%llu\n",
                   (unsigned long long)g_pv_perf.processes,
                   (unsigned long long)g_pv_perf.compiler_processes,
                   (unsigned long long)g_pv_perf.test_processes,
                   (unsigned long long)g_pv_perf.other_processes,
                   (unsigned long long)g_pv_perf.child_wall_us,
                   (unsigned long long)g_pv_perf.child_cpu_us,
                   (unsigned long long)g_pv_perf.compiler_wall_us,
                   (unsigned long long)g_pv_perf.test_wall_us,
                   (unsigned long long)source_bytes,
                   (unsigned long long)output_bytes);
            printf("zbuild-package-ok=1 source=cas recipe=canonical "
                   "network=0\n");
            if (fast_cache_dir)
                printf("zbuild-package-fast-cache=v1 hits=%llu "
                       "misses=%llu reused_bytes=%llu "
                       "admission=local_candidate\n",
                       (unsigned long long)g_pv_fast_hits,
                       (unsigned long long)g_pv_fast_misses,
                       (unsigned long long)g_pv_fast_reused_bytes);
        }
        vcs_package_recipe_free(&recipe);
        vcs_package_manifest_free(&manifest);
        return 0;
    }

    /* Sign + persist. */
    uint8_t attest_id[32] = { 0 };
    enum vcs_package_attest_error aerr =
        vcs_package_attest_id(&att, attest_id);
    if (aerr != VCS_PACKAGE_ATTEST_OK) {
        fprintf(stderr, "%s: internal: attestation invalid: %s\n", PV_LOG,
                vcs_package_attest_error_string(aerr));
        pv_rm_rf(work);
        vcs_package_recipe_free(&recipe);
        vcs_package_manifest_free(&manifest);
        return 5;
    }
    secp256k1_ecdsa_signature esig;
    if (!secp256k1_ecdsa_sign(sign_ctx, &esig, attest_id, secret,
                              secp256k1_nonce_function_rfc6979, NULL)) {
        fprintf(stderr, "%s: internal: ECDSA sign failed\n", PV_LOG);
        pv_rm_rf(work);
        vcs_package_recipe_free(&recipe);
        vcs_package_manifest_free(&manifest);
        return 5;
    }
    secp256k1_ecdsa_signature_serialize_compact(sign_ctx, att.signature,
                                                &esig);
    memory_cleanse(secret, sizeof(secret));
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    aerr = vcs_package_attest_serialize(&att, &wire, &wire_len);
    if (aerr != VCS_PACKAGE_ATTEST_OK) {
        fprintf(stderr, "%s: internal: attestation serialize: %s\n", PV_LOG,
                vcs_package_attest_error_string(aerr));
        pv_rm_rf(work);
        vcs_package_recipe_free(&recipe);
        vcs_package_manifest_free(&manifest);
        return 5;
    }
    char attest_id_hex[65];
    zcl_hex_encode(attest_id, 32, attest_id_hex);
    char dest[4200];
    int dn = snprintf(dest, sizeof(dest), "%s/attestations/%s", store_dir,
                      attest_id_hex);
    bool written =
        dn > 0 && (size_t)dn < sizeof(dest) &&
        pv_atomic_write(dest, wire, wire_len);
    free(wire);
    if (!written) {
        fprintf(stderr, "%s: cannot write %s/attestations/%s\n", PV_LOG,
                store_dir, attest_id_hex);
        pv_rm_rf(work);
        vcs_package_recipe_free(&recipe);
        vcs_package_manifest_free(&manifest);
        return 5;
    }

    /* Produced binaries and objects die with the temp tree — always. */
    if (!pv_rm_rf(work))
        fprintf(stderr, "%s: WARNING: temp tree %s not fully removed\n",
                PV_LOG, work);

    printf("attestation=%s result=%s detail=%s isolation=%s\n",
           attest_id_hex, vcs_package_attest_result_string(att.result_class),
           vcs_package_attest_detail_string(att.detail_code),
           vcs_package_attest_isolation_string(att.isolation));
    vcs_package_recipe_free(&recipe);
    vcs_package_manifest_free(&manifest);
    secp256k1_context_destroy(sign_ctx);
    return 0;
}
