/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_fastobj_carrier: offline proof (docs/work/WIRE_COMPILE_CACHE.md) that
 * a builder's cached objects plus sidecars travel as an ordinary content.v2
 * package to a second cache directory, and the second candidate build reuses
 * eligible objects with byte-identical receipt bytes. Not independent
 * reproduction.
 *
 * Journey (offline, no daemon or network):
 *   1. prepare the tiny-lines fixture package;
 *   2. candidate build #1 with --fast-cache=cacheA (cold);
 *   3. export cacheA into store nodeA as one content.v2 carrier
 *      (zcl-fastobj-carrier.v1/objects/<key>.o|.json);
 *   4. classify it: public shape fastobj-carrier, so a -packagehost=1 node
 *      may announce and serve it;
 *   5. re-export into a third store: identical carrier root;
 *   6. fetch the root store-to-store into nodeB (verify-before-store);
 *   7. admit from nodeB into a fresh cacheB (every entry re-verified);
 *   8. re-export cacheB: same root again;
 *   9. candidate build #2 with --fast-cache=cacheB: every eligible TU is a
 *      HIT (misses == 0);
 *  10. build-report #2 is byte-identical to #1 and both receipts hash to the
 *      same id; the standard receipt ran the fixture's tests and claims
 *      asan,ubsan=clean;
 *  11. a tests/-less fixture is REFUSED (exit 6) in the evidence shape and
 *      BUILDS with --allow-testless-standard (test_ran=false / BUILD_PASS,
 *      asan,ubsan=not-run);
 *  12. a use-after-free fixture under the reproduce shape still EMITS
 *      (TEST_PASS) but its flags say asan,ubsan=findings.
 *
 * Refusal legs (no builds): a torn pair, a sidecar whose object_sha3 lies, an
 * entry under the wrong key, and a carrier whose sidecar does not hash to its
 * filename all refuse at export and at admit, and the public-shape gate
 * refuses the lying carrier a servable shape.
 *
 * The candidate lane forks the package verifier beside this binary; it must
 * exist (make dev-bin), and a missing binary is a loud failure. */

#if defined(__linux__)
#define _GNU_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#include "base/hex.h"
#include "core/uint256.h"
#include "platform/os_proc.h"
#include "platform/fd_path.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "sha3/sha3.h"
#include "vcs/fastobj.h"
#include "vcs/fastobj_carrier.h"
#include "vcs/package_build.h"
#include "vcs/package_content.h"
#include "vcs/package_manifest.h"
#include "vcs/package_prepare.h"
#include "vcs/package_public_shape.h"
#include "vcs/package_store.h"

#if !defined(_WIN32)

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/syscall.h>
#endif

#define FC_CHECK(name, expr) do {                                       \
    if (expr) { printf("  fastobj_carrier: %s... OK\n", (name)); }      \
    else { printf("  fastobj_carrier: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* ── tiny filesystem helpers (same shape as test_zcode_add) ─────────── */

static bool fcw_mkdir_p(const char *path)
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
        if (mkdir(buf, 0700) != 0 && errno != EEXIST) {
            *p = '/';
            return false;
        }
        *p = '/';
    }
    return mkdir(buf, 0700) == 0 || errno == EEXIST;
}

static bool fcw_rm_rf(const char *path)
{
    char normalized[768];
    struct stat st;
    /* A path that is already absent counts as removed. On POSIX hosts the
     * probe uses lstat on the normalized name, which does not follow the
     * final component. Where lstat is an alias of stat (Windows) that does
     * not hold, and this branch is not tested there. */
    if (test_cleanup_path(path, normalized) &&
        lstat(normalized, &st) != 0 && errno == ENOENT)
        return true;
    return test_rm_rf_recursive(path) == 0;
}

static bool fcw_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static bool fcw_write_file(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = len == 0 || fwrite(data, 1, len, f) == len;
    if (fclose(f) != 0)
        ok = false;
    return ok;
}

static uint8_t *fcw_read_file(const char *path, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    struct stat st;
    if (fstat(fileno(f), &st) != 0 || st.st_size < 0 ||
        (uint64_t)st.st_size > (uint64_t)cap) {
        fclose(f);
        return NULL;
    }
    size_t n = (size_t)st.st_size;
    uint8_t *buf = malloc(n ? n : 1u);
    if (!buf || (n && fread(buf, 1, n, f) != n)) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len = n;
    return buf;
}

/* Recursive copy via cp -r — the same subprocess shape the package
 * factory selftest uses for the fixture. */
static bool fcw_copy_tree(const char *src, const char *dst)
{
    char argv_buf[4200];
    if (snprintf(argv_buf, sizeof(argv_buf), "cp -r %s %s", src, dst) >=
        (int)sizeof(argv_buf))
        return false;
    char *argv[] = {(char *)"cp", (char *)"-r", (char *)src, (char *)dst,
                    NULL};
    (void)argv_buf;
    pid_t pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0) {
        execvp("cp", argv);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid)
        return false;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* ── the confined candidate build ───────────────────────────────────── */

/* The package verifier ships beside this binary (never from PATH). */
static bool fcw_worker_path(char *out, size_t cap)
{
    char exe[4096];
    if (!os_proc_exe_path(exe, sizeof(exe)))
        return false;
    char *slash = strrchr(exe, '/');
    if (!slash)
        return false;
    *slash = '\0';
    static const char *const names[] = {
        "z23-package-verify-dev",
        "z23-package-verify",
    };
    for (size_t pass = 0; pass < 2u; pass++) {
        for (size_t i = 0; i < 2u; i++) {
            int w = snprintf(out, cap, "%s/%s",
                             pass == 0 ? exe : "build/bin", names[i]);
            if (w > 0 && (size_t)w < cap && fcw_exists(out))
                return true;
        }
    }
    return false;
}

struct fcw_build_result {
    bool ok;
    int exit_code;
    unsigned long long hits;
    unsigned long long misses;
    unsigned long long processes;
    unsigned long long compiler_processes;
    unsigned long long test_processes;
    unsigned long long other_processes;
    bool perf_complete;
    bool phases_complete;
    bool cache_complete;
    bool source_bytes_unknown;
    bool saw_refusal;
    bool saw_test_23;
    bool saw_test_24;
    bool saw_program_link_error;
    char first_line[256];
    char last_line[256];
};

static bool fcw_phase_partition(const char *text)
{
    const char *total = strstr(text, "compiler_wall_us=");
    const char *phases = strstr(text, "zbuild-package-phases=v1 ");
    unsigned long long compiler, preprocess, compile, link, probe;
    if (!total || !phases) return false;
    if (sscanf(total, "compiler_wall_us=%llu", &compiler) != 1) return false;
    if (sscanf(phases, "zbuild-package-phases=v1 preprocess_dependency_wall_us=%llu "
               "compile_wall_us=%llu link_wall_us=%llu probe_wall_us=%llu",
               &preprocess, &compile, &link, &probe) != 4) return false;
    return preprocess > 0 && compile > 0 && link > 0 && probe > 0 &&
           compiler == preprocess + compile + link + probe;
}

static void fcw_parse_perf(const char *text, struct fcw_build_result *out)
{
    const char *perf = strstr(text, "zbuild-package-perf=v1 ");
    if (!perf)
        return;
    out->perf_complete = sscanf(perf,
        "zbuild-package-perf=v1 processes=%llu "
        "compiler_processes=%llu test_processes=%llu "
        "other_processes=%llu", &out->processes,
        &out->compiler_processes, &out->test_processes,
        &out->other_processes) == 4;
    out->source_bytes_unknown =
        strstr(perf, "source_bytes=unknown ") != NULL;
    out->phases_complete = fcw_phase_partition(text);
}

static int fcw_check_perf(const struct fcw_build_result *cold,
                          const struct fcw_build_result *warm)
{
    int failures = 0;
    FC_CHECK("cold and warm builds count tests independently of compiler names",
             cold->perf_complete && warm->perf_complete &&
             cold->test_processes > 0 &&
             cold->test_processes == warm->test_processes);
    /* The one library TU adds a plan macro probe; both the library and
     * test TU save a compile. Test preprocessing is required on both runs. */
    FC_CHECK("plan warm run saves two compiles and adds one macro probe",
             cold->compiler_processes == warm->compiler_processes + 1u);
    FC_CHECK("process role counts partition all launched children",
             cold->processes == cold->compiler_processes +
                 cold->test_processes + cold->other_processes &&
             warm->processes == warm->compiler_processes +
                 warm->test_processes + warm->other_processes);
    FC_CHECK("candidate source byte coverage is explicitly unknown",
             cold->source_bytes_unknown && warm->source_bytes_unknown);
    FC_CHECK("compiler phases partition measured child time",
             cold->phases_complete && warm->phases_complete);
    return failures;
}

static bool fcw_testless_perf(const struct fcw_build_result *run)
{
    return run->perf_complete && run->test_processes == 0;
}

static void fcw_candidate_options(const char **argv, bool allow_testless,
                                   bool with_plan, const char *plan_arg)
{
    size_t n = 0;
    if (allow_testless)
        argv[n++] = "--allow-testless-standard";
    if (with_plan)
        argv[n++] = plan_arg;
    argv[n] = NULL;
}

struct fcw_cand_args {
    char source_arg[4200], recipe_arg[4200], emit_arg[4096],
         lock_arg[128], fast_arg[4096], name_arg[128], cpu_arg[64],
         plan_arg[4200];
};

/* Formats every candidate-build flag; false when any value would not fit. */
static bool fcw_candidate_format(struct fcw_cand_args *ca, const char *pkg_abs,
                                 const char *recipe_abs, const char *emit_dir,
                                 const char *lock_hex, const char *cache_dir)
{
    return !(snprintf(ca->source_arg, sizeof(ca->source_arg),
                      "--zbuild-package-source=%s", pkg_abs) >=
             (int)sizeof(ca->source_arg) ||
             snprintf(ca->recipe_arg, sizeof(ca->recipe_arg),
                      "--zbuild-package-recipe=%s", recipe_abs) >=
             (int)sizeof(ca->recipe_arg) ||
             snprintf(ca->emit_arg, sizeof(ca->emit_arg), "--emit=%s", emit_dir) >=
             (int)sizeof(ca->emit_arg) ||
             snprintf(ca->lock_arg, sizeof(ca->lock_arg), "--lock-root=%s", lock_hex) >=
             (int)sizeof(ca->lock_arg) ||
             snprintf(ca->fast_arg, sizeof(ca->fast_arg), "--fast-cache=%s",
                      cache_dir) >= (int)sizeof(ca->fast_arg) ||
             snprintf(ca->name_arg, sizeof(ca->name_arg),
                      "--zbuild-package-name=fixture/tiny-lines") >=
             (int)sizeof(ca->name_arg) ||
             snprintf(ca->plan_arg, sizeof(ca->plan_arg), "--plan=%s.plan", emit_dir) >=
             (int)sizeof(ca->plan_arg) ||
             snprintf(ca->cpu_arg, sizeof(ca->cpu_arg),
                      "--zbuild-package-max-cpu-seconds=120") >=
             (int)sizeof(ca->cpu_arg));
}

/* Forks the worker with stdout and stderr on one pipe. Returns the child pid,
 * or -1 with both pipe ends closed. */
static pid_t fcw_candidate_spawn(const char *worker, const char *const *argv,
                                 int fds[2])
{
    if (pipe(fds) != 0)
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        if (dup2(fds[1], STDOUT_FILENO) < 0 ||
            dup2(fds[1], STDERR_FILENO) < 0)
            _exit(126);
        close(fds[0]);
        close(fds[1]);
        execv(worker, (char *const *)argv);
        _exit(127);
    }
    return pid;
}

/* Drain until EOF, a 1 MiB cap, or 300 s of silence — whichever
 * comes first. */
/* Returns a NUL-terminated buffer (NULL on allocation failure) and its length. */
static char *fcw_candidate_drain(int fd, size_t *len_out)
{
    size_t cap = 1024u * 1024u, len = 0;
    *len_out = 0;
    char *text = malloc(cap);
    if (!text)
        return NULL;
    int idle = 0;
    while (len + 1u < cap && idle < 300) {
        struct pollfd pfd = {fd, POLLIN, 0};
        int pr = poll(&pfd, 1, 1000);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (pr == 0) {
            idle++;
            continue;
        }
        ssize_t got = read(fd, text + len, cap - len - 1u);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (got == 0)
            break; /* EOF */
        len += (size_t)got;
        idle = 0;
    }
    text[len] = '\0';
    *len_out = len;
    return text;
}

/* Reap: up to 60 s past EOF for the exit syscall, then SIGKILL. */
/* Returns true when the child had to be killed. */
static bool fcw_candidate_reap(pid_t pid, int *status)
{
    bool reaped = false, killed = false;
    for (int i = 0; i < 60 && !reaped; i++) {
        if (waitpid(pid, status, WNOHANG) == pid) {
            reaped = true;
            break;
        }
        sleep(1); /* real-clock: pre-existing bounded poll loop, seeded when check_no_real_clock_test_deadline.sh was introduced */
    }
    if (!reaped) {
        kill(pid, SIGKILL);
        killed = true;
        (void)waitpid(pid, status, 0);
    }
    return killed;
}

/* Reads the first line, the last line and every marker from the merged output. */
static void fcw_candidate_collect(struct fcw_build_result *out, char *text,
                                  size_t len)
{
    snprintf(out->first_line, sizeof(out->first_line), "%.255s", text);
    const char *end = text + len;
    if (end > text && end[-1] == '\n')
        end--;
    const char *tail = end;
    while (tail > text && tail[-1] != '\n')
        tail--;
    snprintf(out->last_line, sizeof(out->last_line), "%.*s",
             (int)(end - tail), tail);
    out->saw_refusal =
        strstr(text, "zbuild-package-standard-refused=1") != NULL;
    out->saw_test_23 = strstr(text, "exit 23, expected 0") != NULL;
    out->saw_test_24 = strstr(text, "exit 24, expected 0") != NULL;
    out->saw_program_link_error =
        strstr(text, "detail=gcc: collect2: error: ld returned") != NULL;
    fcw_parse_perf(text, out);
    char *line = strstr(text, "zbuild-package-fast-cache=v1");
    if (line)
        out->cache_complete = sscanf(line,
                     "zbuild-package-fast-cache=v1 hits=%llu "
                     "misses=%llu", &out->hits, &out->misses) == 2;
}

/* Spawn the verifier in candidate proof mode with a fast cache, capture
 * merged stdout/stderr, and parse the fast-cache counters line.
 * allow_testless passes --allow-testless-standard. */
static void fcw_candidate_build(const char *worker, const char *root_hex,
                                const char *pkg_abs, const char *recipe_abs,
                                const char *emit_dir, const char *lock_hex,
                                const char *cache_dir, bool allow_testless,
                                bool with_plan,
                                struct fcw_build_result *out)
{
    memset(out, 0, sizeof(*out));
    out->exit_code = -1;
    struct fcw_cand_args ca;
    if (!fcw_candidate_format(&ca, pkg_abs, recipe_abs, emit_dir, lock_hex,
                              cache_dir))
        return;
    const char *argv[] = {worker,       root_hex,     ca.source_arg,
                          ca.recipe_arg, ca.name_arg,
                          "--zbuild-package-profile=standard",
                          ca.cpu_arg,   ca.emit_arg,  ca.lock_arg,
                          ca.fast_arg, "--require-full-isolation",
                          NULL, NULL, NULL};
    fcw_candidate_options(argv + 11, allow_testless, with_plan, ca.plan_arg);
    int fds[2];
    pid_t pid = fcw_candidate_spawn(worker, argv, fds);
    if (pid < 0)
        return;
    close(fds[1]);
    size_t len = 0;
    char *text = fcw_candidate_drain(fds[0], &len);
    int status = 0;
    bool killed = fcw_candidate_reap(pid, &status);
    close(fds[0]);
    out->exit_code = !killed && WIFEXITED(status) ? WEXITSTATUS(status)
                                                  : -1;
    out->ok = !killed && out->exit_code == 0;
    if (text) {
        fcw_candidate_collect(out, text, len);
        free(text);
    }
}

/* ── refusal-leg helpers ────────────────────────────────────────────── */

/* Find any one complete cache entry key (the first <62 hex>.o member the
 * directory walk meets). */
static const char *fcw_find(const uint8_t *hay, size_t len, const char *needle);

static bool fcw_object_contains(const char *shard, const char *name,
                                 const char *needle)
{
    if (!needle) return true;
    char path[4400];
    if (snprintf(path, sizeof(path), "%s/%s", shard, name) >= (int)sizeof(path))
        return false;
    size_t len = 0;
    uint8_t *bytes = fcw_read_file(path, 1024u * 1024u, &len);
    bool found = bytes && fcw_find(bytes, len, needle) != NULL;
    free(bytes);
    return found;
}

static bool fcw_matching_entry(const char *cache_dir, char key_out[65],
                                const char *needle)
{
    char objects[4096];
    if (snprintf(objects, sizeof(objects), "%s/objects", cache_dir) >=
        (int)sizeof(objects))
        return false;
    DIR *shards = opendir(objects);
    if (!shards)
        return false;
    struct dirent *sh;
    bool found = false;
    while (!found && (sh = readdir(shards)) != NULL) {
        if (strlen(sh->d_name) != 2)
            continue;
        char shard[4096];
        if (snprintf(shard, sizeof(shard), "%s/%s", objects, sh->d_name) >=
            (int)sizeof(shard))
            continue;
        DIR *d = opendir(shard);
        if (!d)
            continue;
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strlen(e->d_name) == 64 &&
                strcmp(e->d_name + 62, ".o") == 0 &&
                fcw_object_contains(shard, e->d_name, needle)) {
                key_out[0] = sh->d_name[0];
                key_out[1] = sh->d_name[1];
                memcpy(key_out + 2, e->d_name, 62);
                key_out[64] = '\0';
                found = true;
                break;
            }
        }
        closedir(d);
    }
    closedir(shards);
    return found;
}

static bool fcw_first_entry(const char *cache_dir, char key_out[65])
{
    return fcw_matching_entry(cache_dir, key_out, NULL);
}

/* Bytes-forward substring search over a non-NUL-terminated buffer. */
static const char *fcw_find(const uint8_t *hay, size_t len,
                            const char *needle)
{
    size_t n = strlen(needle);
    if (len < n)
        return NULL;
    for (size_t i = 0; i + n <= len; i++) {
        if (memcmp(hay + i, needle, n) == 0)
            return (const char *)(hay + i);
    }
    return NULL;
}

#if defined(__linux__) || defined(__APPLE__)
/* Assembler witness: bytes read by .incbin are absent from -E output. */
struct fcw_asm_fixture {
    char pkg[4096], data[4096], source[4096], recipe[4096];
    char cache[4096], fresh[4096], emit[3][4096];
};

static bool fcw_asm_path(char out[4096], const char *base, const char *name)
{
    int n = snprintf(out, 4096, "%s/%s", base, name);
    return n > 0 && n < 4096;
}

static bool fcw_asm_fixture_init(struct fcw_asm_fixture *f, const char *base,
                                  bool attribute)
{
    if (!fcw_asm_path(f->pkg, base, attribute ? "attribute-pkg" : "asm-pkg") ||
        !fcw_asm_path(f->data, f->pkg, "README.md") ||
        !fcw_asm_path(f->source, f->pkg, "src/tiny_lines.c") ||
        !fcw_asm_path(f->recipe, base, "asm-recipe.wire") ||
        !fcw_asm_path(f->cache, base, "asm-cache") ||
        !fcw_asm_path(f->fresh, base, "asm-fresh") ||
        !fcw_copy_tree("tests/harness/fixtures/zcode/tiny-lines", f->pkg))
        return false;
    for (size_t i = 0; i < 3; i++) {
        char name[32];
        (void)snprintf(name, sizeof(name), "asm-emit-%zu", i);
        if (!fcw_asm_path(f->emit[i], base, name)) return false;
    }
    FILE *source = fopen(f->source, "ab");
    if (!source) return false;
#if defined(__APPLE__)
    const char *format = "\n#define FCW_ASM __asm__\n"
          "FCW_ASM(\".data\\n.incbin \\\"%s\\\"\\n.text\\n\");\n";
#else
    const char *format = attribute
        ? "\nconst unsigned char fcw_section_data __attribute__((section("
          "\".rodata\\n.incbin \\\"%s\\\"\\n#\"))) = 7;\n"
        : "\n#define FCW_ASM __asm__\n"
          "FCW_ASM(\".pushsection .rodata\\n.incbin \\\"%s\\\"\\n.popsection\\n\");\n";
#endif
    int written = fprintf(source, format, f->data);
    bool ok = written > 0;
    if (fclose(source) != 0) ok = false;
    return ok;
}

static bool fcw_asm_build(const struct fcw_asm_fixture *f, const char *worker,
                          const struct pubkey *pk, size_t run,
                          struct fcw_build_result *result, uint8_t root[32])
{
    struct vcs_package_prepared prep;
    vcs_package_prepared_init(&prep);
    struct vcs_package_prepare_options opts = {0};
    opts.dir = f->pkg;
    opts.publisher_sequence = 1;
    memcpy(opts.publisher_pubkey, pk->vch, COMPRESSED_PUBLIC_KEY_SIZE);
    char detail[512], root_hex[65], lock_hex[65];
    bool ok = vcs_package_prepare(&opts, &prep, detail, sizeof(detail)) ==
                  VCS_PACKAGE_PREPARE_OK;
    if (ok) {
        memcpy(root, prep.package_root, 32);
        zcl_hex_encode(root, 32, root_hex);
        zcl_hex_encode(prep.lock_root, 32, lock_hex);
        ok = fcw_write_file(f->recipe, prep.recipe_wire, prep.recipe_wire_len);
    }
    if (ok) {
        fcw_candidate_build(worker, root_hex, f->pkg, f->recipe, f->emit[run],
                            lock_hex, run == 2 ? f->fresh : f->cache,
                            false, run == 1, result);
        ok = result->ok;
    }
    vcs_package_prepared_free(&prep);
    return ok;
}

static bool fcw_asm_same_output(const char *left, const char *right,
                                const char *name, bool equal)
{
    char a[4096], b[4096];
    if (!fcw_asm_path(a, left, name) || !fcw_asm_path(b, right, name))
        return false;
    size_t an = 0, bn = 0;
    uint8_t *av = fcw_read_file(a, 1024u * 1024u, &an);
    uint8_t *bv = fcw_read_file(b, 1024u * 1024u, &bn);
    bool same = av && bv && an == bn && memcmp(av, bv, an) == 0;
    bool ok = av && bv && same == equal;
    free(av); free(bv);
    return ok;
}

static bool fcw_cache_entry_is_test(const char *cache)
{
    char key[65], path[4400];
    if (!fcw_first_entry(cache, key) ||
        snprintf(path, sizeof(path), "%s/objects/%.2s/%s.json", cache,
                 key, key + 2) >= (int)sizeof(path)) return false;
    size_t len = 0;
    uint8_t *data = fcw_read_file(path, 65536, &len);
    bool ok = data && fcw_find(data, len,
        "\"source\":\"tests/test_tiny_lines.c\"") != NULL;
    free(data);
    return ok;
}

static int fcw_asm_bypass(const char *base, const char *worker,
                          const struct pubkey *pk, bool attribute)
{
    int failures = 0;
    struct fcw_asm_fixture f;
    bool ready = fcw_asm_fixture_init(&f, base, attribute);
    FC_CHECK(attribute ? "section-attribute incbin fixture prepared separately"
                       : "macro-expanded incbin fixture prepared separately", ready);
    if (!ready) return failures;
    uint8_t roots[3][32];
    struct fcw_build_result runs[3] = {0};
    for (size_t i = 0; i < 3; i++) {
        const char *data = i == 0 ? "OLD-incbin-payload\n" : "NEW-incbin-payload\n";
        bool built = fcw_write_file(f.data, data, strlen(data)) &&
            fcw_asm_build(&f, worker, pk, i, &runs[i], roots[i]);
        FC_CHECK("incbin build runs normal compilation and tests", built);
        if (!built) return failures;
        FC_CHECK("only safe test source participates in asm fixture cache",
                 runs[i].cache_complete && runs[i].hits == (i == 1 ? 1u : 0u) &&
                 runs[i].misses == (i == 1 ? 0u : 1u));
    }
    FC_CHECK("the sole object in each asm cache belongs to the safe test",
             fcw_cache_entry_is_test(f.cache) && fcw_cache_entry_is_test(f.fresh));
    FC_CHECK("data mutation changes package root; control has identical inputs",
             memcmp(roots[0], roots[1], 32) != 0 &&
             memcmp(roots[1], roots[2], 32) == 0);
    FC_CHECK("incbin data mutation changes actual emitted library bytes",
             fcw_asm_same_output(f.emit[0], f.emit[1], "lib/libtiny-lines.a", false));
    FC_CHECK("plan shared-cache report equals no-plan empty-cache control",
             fcw_asm_same_output(f.emit[1], f.emit[2], "build-report", true));
    FC_CHECK("plan shared-cache library equals no-plan empty-cache control",
             fcw_asm_same_output(f.emit[1], f.emit[2], "lib/libtiny-lines.a", true));
    return failures;
}
static bool fcw_attribute_spelling(const char *base, const char *worker,
                                   const struct pubkey *pk, const char *suffix,
                                   bool reusable)
{
    struct fcw_asm_fixture f;
    if (!fcw_mkdir_p(base) || !fcw_asm_fixture_init(&f, base, true)) return false;
    size_t len = 0;
    uint8_t *source = fcw_read_file(
        "tests/harness/fixtures/zcode/tiny-lines/src/tiny_lines.c", 65536, &len);
    if (!source) return false;
    bool ok = fcw_write_file(f.source, source, len);
    free(source);
    FILE *out = ok ? fopen(f.source, "ab") : NULL;
    if (!out) return false;
    ok = fputs(suffix, out) >= 0;
    if (fclose(out) != 0) ok = false;
    struct fcw_build_result result = {0};
    uint8_t root[32];
    ok = ok && fcw_asm_build(&f, worker, pk, 0, &result, root);
    return ok && result.cache_complete && result.hits == 0 &&
           result.misses == (reusable ? 2u : 1u);
}
#endif

#if defined(__APPLE__)
static int fcw_apple_attribute_spellings(const char *base, const char *worker,
                                        const struct pubkey *pk)
{
    static const char *const cases[] = {
        "\nextern int fcw_alias(void) __asm__(\"_\" \"fcw_symbol\" \"$DARWIN_EXTSN\");\n"
        "const int fcw_swift __attribute__((__swift_attr__(\"nonisolated(unsafe)\"))) = 1;\n"
        "extern int fcw_availability(void) __attribute__((availability(swift, unavailable, message=\"SDK metadata\")));\n",
        "\nconst int fcw_swift __attribute__((__swift_attr__(\"nonisolated(unsafe)\"), section(\"__DATA,fcw_guard\"))) = 1;\n",
        "\nconst int fcw_availability __attribute__((availability(swift, unavailable, message=\"SDK metadata\"), section(\"__DATA,fcw_guard\"))) = 1;\n",
        "\nconst int fcw_swift __attribute__((__swift_attr__(\"nonisolated(safe)\"))) = 1;\n",
        "\nextern int fcw_availability(void) __attribute__((availability(swift, unavailable, message=\"escaped\\n\")));\n",
        "\nextern int fcw_alias(void) __asm__(\"fcw_symbol/unsafe\");\n",
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char path[4096], name[48];
        (void)snprintf(name, sizeof(name), "apple-attribute-spelling-%zu", i);
        bool ok = fcw_asm_path(path, base, name) &&
            fcw_attribute_spelling(path, worker, pk, cases[i], i == 0);
        FC_CHECK(name, ok);
    }
    return failures;
}
#endif

#if defined(__linux__)

static int fcw_attribute_spellings(const char *base, const char *worker,
                                  const struct pubkey *pk)
{
    static const char *const cases[] = {
        "\nconst int fcw_attr __attribute__((section(\"guard_data\"))) = 1;\n",
        "\nconst int fcw_attr __attribute((section(\"guard_data\"))) = 1;\n",
        "\n[ [gnu::used] ] const int fcw_attr = 1;\n",
        "\n<: <:gnu::used:> :> const int fcw_attr = 1;\n",
        "\n_Pragma(\"GCC diagnostic push\")\nconst int fcw_attr = 1;\n",
        "\nconst int __attribute__suffix __attribute__((aligned(8))) = 1;\n",
        "\nextern int fcw_alias(void) __asm__(\"\" \"fcw_symbol\");\n",
        "\nextern int fcw_alias(void) __asm__(\"fcw\\x5fsymbol\");\n",
        "\nextern int fcw_alias(void) __asm__(\"fcw_symbol\");\n"
        "const int fcw_attr __attribute__((section(\"guard_data\"))) = 1;\n",
        "\nextern int fcw_alias(void) __asm__(\"fcw_symbol\");\n"
        "__asm__(\".text\");\n",
        "\n[[nodiscard]] int fcw_nodiscard(void);\n",
        "\n[[nodiscard(\"reason\")]] int fcw_nodiscard(void);\n",
        "\n[[nodiscard]] int fcw_nodiscard(void);\n"
        "const int fcw_attr __attribute__((section(\"guard_data\"))) = 1;\n",
        "\nextern int fcw_diag(void) __attribute__((__warning__(\"one \" \"two\")));\n",
        "\nextern int fcw_diag(void) __attribute__((__error__(\"unused\")));\n",
        "\nextern int fcw_diag(void) __attribute__((__warning__(\"escaped\\n\")));\n",
        "\nextern int fcw_diag(void) __attribute__((__warning__(\"ok\"), section(\"guard_text\")));\n",
        "\nextern int fcw_diag(void) __attribute__((__warning__(\"ok\")));\n"
        "__asm__(\".text\");\n",
        "\nextern int fcw_diag(void) __attribute__((__warning__(\"# [] < : asm\")));\n",
        "\n_Pragma(\"GCC diagnostic warning \\\"-Wunused-function\\\"\")\n",
        "\n_Pragma(\"GCC diagnostic push\")\n"
        "_Pragma(\"GCC diagnostic ignored \\\"-Wcast-qual\\\"\")\n"
        "_Pragma(\"GCC diagnostic pop\")\n",
        "\n_Pragma(\"GCC diagnostic push\")\n__asm__(\".text\");\n",
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char path[4096], name[48];
        (void)snprintf(name, sizeof(name), "attribute-spelling-%zu", i);
        bool ok = fcw_asm_path(path, base, name) &&
            fcw_attribute_spelling(path, worker, pk, cases[i],
                                   i == 4 || i == 5 || i == 6 || i == 10 ||
                                   i == 13 || i == 14 || i == 18 || i == 20);
        FC_CHECK(name, ok);
    }
    return failures;
}

static int fcw_attribute_bypass(const char *base, const char *worker,
                                const struct pubkey *pk)
{
    int failures = 0;
    char attribute_base[4096];
    bool ready = fcw_asm_path(attribute_base, base, "attribute") &&
                 fcw_mkdir_p(attribute_base);
    FC_CHECK("attribute fixture directory prepared", ready);
    if (ready) failures += fcw_asm_bypass(attribute_base, worker, pk, true);
    failures += fcw_attribute_spellings(base, worker, pk);
    return failures;
}

static bool fcw_test_cache_fixture(struct fcw_asm_fixture *f, const char *base)
{
    bool ready = fcw_asm_path(f->pkg, base, "test-cache-pkg") &&
        fcw_copy_tree("tests/harness/fixtures/zcode/tiny-lines", f->pkg) &&
        fcw_asm_path(f->source, f->pkg, "tests/test_tiny_lines.c") &&
        fcw_asm_path(f->data, f->pkg, "tests/fcw_test_gate.h") &&
        fcw_asm_path(f->recipe, base, "test-cache-recipe.wire") &&
        fcw_asm_path(f->cache, base, "test-cache-negative");
    const char *source = "#include \"fcw_test_gate.h\"\nint main(void) {\n"
        "#if defined(__GNUC__) && !defined(__clang__)\nreturn FCW_EXIT;\n"
        "#else\nreturn 0;\n#endif\n}\n";
    return ready && fcw_write_file(f->source, source, strlen(source));
}

static bool fcw_program_cache_fixture(struct fcw_asm_fixture *f, const char *base)
{
    char manifest[4096], app[4096];
    const char *json = "{\"schema\":1,\"name\":\"fixture/tiny-lines\","
        "\"semver\":\"0.1.0\",\"language\":\"c23\",\"license\":\"MIT\","
        "\"include_dir\":\"include\",\"source_dir\":\"src\","
        "\"programs\":[\"app/main.c\"],\"dependencies\":[]}\n";
    const char *source = "#include \"gate.h\"\nint main(void) { return FCW_EXIT; }\n";
    return fcw_asm_path(f->pkg, base, "program-cache-pkg") &&
        fcw_copy_tree("tests/harness/fixtures/zcode/tiny-lines", f->pkg) &&
        fcw_asm_path(manifest, f->pkg, "zcode-package.json") &&
        fcw_write_file(manifest, json, strlen(json)) &&
        fcw_asm_path(app, f->pkg, "app") && fcw_mkdir_p(app) &&
        fcw_asm_path(f->source, app, "main.c") &&
        fcw_write_file(f->source, source, strlen(source)) &&
        fcw_asm_path(f->data, app, "gate.h") &&
        fcw_asm_path(f->recipe, base, "program-cache-recipe.wire") &&
        fcw_asm_path(f->cache, base, "program-cache");
}

static const char *fcw_program_cache_header(size_t run)
{
    if (run < 2) return "#define FCW_EXIT 0\n";
    if (run == 2) return "#define FCW_EXIT 23\n";
    if (run == 3) return
        "#if defined(__GNUC__) && !defined(__clang__)\n"
        "#define FCW_EXIT fcw_missing_program_header_symbol\n"
        "#else\n#define FCW_EXIT 0\n#endif\n";
    return "#if defined(__GNUC__) && !defined(__clang__)\n"
        "extern int fcw_missing_link(void);\n#define FCW_EXIT fcw_missing_link()\n"
        "#else\n#define FCW_EXIT 0\n#endif\n";
}

static bool fcw_program_cache_positive(const struct fcw_asm_fixture *f,
                                       const char *base, size_t run,
                                       const struct fcw_build_result *result,
                                       bool passed)
{
    static const unsigned hits[] = {0, 3, 2}, misses[] = {3, 0, 1};
    if (!passed || result->hits != hits[run] || result->misses != misses[run])
        return false;
    if (run != 2) return true;
    char warm[4096];
    return fcw_asm_path(warm, base, "program-cache-1") &&
        fcw_asm_same_output(warm, f->emit[1], "bin/tiny-lines", false);
}

static bool fcw_program_cache_expected(const struct fcw_asm_fixture *f,
                                       const char *base, size_t run,
                                       const struct fcw_build_result *result,
                                       bool passed)
{
    if (run < 3) return fcw_program_cache_positive(f, base, run, result, passed);
    if (passed || result->exit_code != 6 || !result->saw_refusal) return false;
    if (run == 3) return true;
    char key[65];
    /* Refusals emit no success counters. Observe the stored program
     * object before repeating its failing link with the same cache. */
    return result->saw_program_link_error &&
        fcw_matching_entry(f->cache, key, "fcw_missing_link");
}

static int fcw_program_cache_probe(const char *base, const char *worker,
                                   const struct pubkey *pk)
{
    int failures = 0;
    struct fcw_asm_fixture f = {0};
    bool ready = fcw_program_cache_fixture(&f, base);
    FC_CHECK("program object cache fixture prepared", ready);
    if (!ready) return failures;
    for (size_t i = 0; i < 6; i++) {
        char name[48];
        snprintf(name, sizeof(name), "program-cache-%zu", i);
        const char *header = fcw_program_cache_header(i);
        bool inputs = fcw_asm_path(f.emit[1], base, name) &&
            fcw_write_file(f.data, header, strlen(header));
        struct fcw_build_result result = {0};
        uint8_t root[32];
        bool passed = inputs && fcw_asm_build(&f, worker, pk, 1, &result, root);
        FC_CHECK(name, inputs && fcw_program_cache_expected(&f, base, i,
                                                             &result, passed));
    }
    return failures;
}

static bool fcw_expected_test_refusal(const struct fcw_build_result *result,
                                      size_t run)
{
    return result->exit_code == 6 && result->saw_refusal &&
           (run == 3 ? result->saw_test_24 : result->saw_test_23);
}

static int fcw_test_cache_failure(const char *base, const char *worker,
                                   const struct pubkey *pk)
{
    int failures = 0;
    struct fcw_asm_fixture f = {0};
    bool ready = fcw_test_cache_fixture(&f, base);
    const char *changed = "int main(void) {\n"
        "#if defined(__GNUC__) && !defined(__clang__)\nreturn 24;\n"
        "#else\nreturn 0;\n#endif\n}\n";
    FC_CHECK("test-only header cache fixture prepared", ready);
    if (!ready) return failures;
    for (size_t i = 0; i < 4; i++) {
        char name[48];
        snprintf(name, sizeof(name), "test-cache-negative-%zu", i);
        const char *header = i == 0 ? "#define FCW_EXIT 0\n" : "#define FCW_EXIT 23\n";
        bool inputs = fcw_asm_path(f.emit[1], base, name) &&
            fcw_write_file(f.data, header, strlen(header));
        if (i == 3) inputs = inputs && fcw_write_file(f.source, changed, strlen(changed));
        struct fcw_build_result result = {0};
        uint8_t root[32];
        bool passed = inputs && fcw_asm_build(&f, worker, pk, 1, &result, root);
        if (i == 0) {
            FC_CHECK("test-only header baseline caches both objects",
                     passed && result.misses == 2 && result.hits == 0);
        } else {
            FC_CHECK("changed or cached failing GCC test still refuses acceptance",
                     inputs && !passed && fcw_expected_test_refusal(&result, i));
        }
    }
    return failures;
}
#endif

static int fcw_fetch_damage(struct vcs_package_store *dst,
                            struct vcs_package_store *src,
                            const uint8_t root[32], const char *path,
                            unsigned damage)
{
    int failures = 0;
    char err[512];
    uint8_t *original = NULL;
    size_t original_len = 0;
    bool saved = vcs_package_store_get_chunk_at(
        src, root, 0, 0, &original, &original_len) == VCS_PACKAGE_STORE_OK;
    FC_CHECK("resume fixture source bytes", saved && original_len > 0);
    if (!saved || original_len == 0) {
        free(original);
        return failures;
    }
    original[0] ^= 1;
    bool damaged = damage == 0 ? unlink(path) == 0 :
        fcw_write_file(path, original, original_len);
    free(original);
    FC_CHECK("damage indexed destination chunk", damaged);
    bool resumed = vcs_fastobj_carrier_fetch(dst, src, root, NULL, err, sizeof(err));
    uint8_t *chunk = NULL;
    size_t chunk_len = 0;
    bool readable = vcs_package_store_get_chunk_at(
        dst, root, 0, 0, &chunk, &chunk_len) == VCS_PACKAGE_STORE_OK;
    FC_CHECK(damage == 0 ? "resume repairs missing destination bytes" :
             "resume repairs corrupt destination bytes", resumed && readable);
    free(chunk);
    FC_CHECK("restore fixture between independent damage cases",
             vcs_fastobj_carrier_fetch(dst, src, root, NULL, err, sizeof(err)));
    return failures;
}

static int fcw_fetch_io_refusal(struct vcs_package_store *dst,
                               struct vcs_package_store *src,
                               const uint8_t root[32], const char *path)
{
    int failures = 0;
    char saved[4096], err[512] = "";
    bool moved = snprintf(saved, sizeof(saved), "%s.saved", path) < (int)sizeof(saved) &&
        rename(path, saved) == 0;
    FC_CHECK("save destination chunk for IO refusal", moved);
    if (!moved) return failures;
    bool directory = mkdir(path, 0700) == 0;
    FC_CHECK("replace chunk with an unreadable object type", directory);
    if (directory) {
        FC_CHECK("destination IO error refuses fetch with context",
                 !vcs_fastobj_carrier_fetch(dst, src, root, NULL, err, sizeof(err)) &&
                 strstr(err, "destination chunk read") != NULL);
        FC_CHECK("IO refusal preserves the unexpected directory", rmdir(path) == 0);
    }
    FC_CHECK("restore destination chunk after IO refusal", rename(saved, path) == 0);
    return failures;
}

static int fcw_fetch_reuse(struct vcs_package_store *dst,
                           struct vcs_package_store *src,
                           const uint8_t root[32], const char *source_dir)
{
    int failures = 0;
    char cas[4096], saved[4096], err[512];
    bool paths = snprintf(cas, sizeof(cas), "%s/zcode/cas", source_dir) < (int)sizeof(cas) &&
        snprintf(saved, sizeof(saved), "%s/zcode/cas.saved", source_dir) < (int)sizeof(saved);
    bool hidden = paths && rename(cas, saved) == 0;
    FC_CHECK("hide source chunks for destination reuse", hidden);
    if (!hidden) return failures;
    FC_CHECK("verified destination reuse does not need source chunks",
             vcs_fastobj_carrier_fetch(dst, src, root, NULL, err, sizeof(err)));
    FC_CHECK("restore source chunk directory", rename(saved, cas) == 0);
    return failures;
}

static int fcw_fetch_resume(struct vcs_package_store *dst,
                            struct vcs_package_store *src,
                            const uint8_t root[32], const char *dest_dir,
                            const char *source_dir, bool fetched)
{
    if (!fetched) return 0; /* The caller already records the initial failure. */
    int failures = 0;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    struct vcs_package_manifest manifest = {0};
    bool parsed = vcs_package_store_get_manifest_wire(
        src, root, &wire, &wire_len) == VCS_PACKAGE_STORE_OK &&
        vcs_package_manifest_parse(wire, wire_len, &manifest);
    free(wire);
    FC_CHECK("resume fixture manifest", parsed && manifest.count > 0);
    if (!parsed) return failures;
    if (manifest.count > 0 && manifest.files[0].chunk_count > 0) {
        char hash[65], path[4096];
        zcl_hex_encode(manifest.files[0].chunk_hashes, 32, hash);
        int n = snprintf(path, sizeof(path), "%s/zcode/cas/sha3/%.2s/%s",
                         dest_dir, hash, hash);
        bool bounded = n > 0 && n < (int)sizeof(path);
        FC_CHECK("resume fixture path bounded", bounded);
        if (bounded) {
            failures += fcw_fetch_damage(dst, src, root, path, 0);
            failures += fcw_fetch_damage(dst, src, root, path, 1);
            failures += fcw_fetch_io_refusal(dst, src, root, path);
            failures += fcw_fetch_reuse(dst, src, root, source_dir);
        }
    }
    vcs_package_manifest_free(&manifest);
    return failures;
}

static int fcw_linked_sidecar_refusal(const char *base, const char *cache,
                                     const char *key,
                                     struct vcs_package_store *store,
                                     uint8_t root[32],
                                     struct vcs_fastobj_carrier_stats *stats,
                                     char *err, size_t err_cap)
{
    int failures = 0;
    char linked[4096], object[4096], sidecar[4096], outside[4096];
    bool prepared = snprintf(linked, sizeof(linked), "%s/linked", base) <
                        (int)sizeof(linked) &&
                    fcw_rm_rf(linked) && fcw_copy_tree(cache, linked) &&
                    vcs_fastobj_cache_paths(linked, key, object,
                                            sizeof(object), sidecar,
                                            sizeof(sidecar)) &&
                    snprintf(outside, sizeof(outside), "%s/outside-sidecar",
                             base) < (int)sizeof(outside) &&
                    rename(sidecar, outside) == 0 &&
                    symlink("../../../outside-sidecar", sidecar) == 0;
    FC_CHECK("export linked sidecar fixture is prepared", prepared);
    if (!prepared)
        return failures;
    bool refused = !vcs_fastobj_carrier_export(linked, store, root, stats,
                                               err, err_cap);
    FC_CHECK("export refuses a linked cache sidecar",
             refused && strstr(err, "sidecar unreadable"));
    bool restored = unlink(sidecar) == 0 &&
                    rename(outside, sidecar) == 0;
    FC_CHECK("same sidecar as real leaf exports",
             restored && vcs_fastobj_carrier_export(linked, store, root,
                                                    stats, err, err_cap));
    return failures;
}

static int fcw_linked_object_refusal(const char *base, const char *cache,
                                    const char *key,
                                    struct vcs_package_store *store,
                                    uint8_t root[32],
                                    struct vcs_fastobj_carrier_stats *stats,
                                    char *err, size_t err_cap)
{
    int failures = 0;
    char linked[4096], object[4096], sidecar[4096], outside[4096];
    bool prepared = snprintf(linked, sizeof(linked), "%s/linked-object",
                             base) < (int)sizeof(linked) &&
                    fcw_rm_rf(linked) && fcw_copy_tree(cache, linked) &&
                    vcs_fastobj_cache_paths(linked, key, object,
                                            sizeof(object), sidecar,
                                            sizeof(sidecar)) &&
                    snprintf(outside, sizeof(outside), "%s/outside-object",
                             base) < (int)sizeof(outside) &&
                    rename(object, outside) == 0 &&
                    symlink("../../../outside-object", object) == 0;
    FC_CHECK("export linked object fixture is prepared", prepared);
    if (!prepared)
        return failures;
    bool refused = !vcs_fastobj_carrier_export(linked, store, root, stats,
                                               err, err_cap);
    FC_CHECK("export refuses a linked cache object", refused);
    bool restored = unlink(object) == 0 &&
                    rename(outside, object) == 0;
    FC_CHECK("same object as real leaf exports",
             restored && vcs_fastobj_carrier_export(linked, store, root,
                                                    stats, err, err_cap));
    return failures;
}

static int fcw_linked_shard_refusal(const char *base, const char *cache,
                                   const char *key,
                                   struct vcs_package_store *store,
                                   uint8_t root[32],
                                   struct vcs_fastobj_carrier_stats *stats,
                                   char *err, size_t err_cap)
{
    int failures = 0;
    char linked[4096], shard[4096], outside[4096];
    bool prepared = snprintf(linked, sizeof(linked), "%s/linked-shard",
                             base) < (int)sizeof(linked) &&
                    fcw_rm_rf(linked) && fcw_copy_tree(cache, linked) &&
                    snprintf(shard, sizeof(shard), "%s/objects/%.2s",
                             linked, key) < (int)sizeof(shard) &&
                    snprintf(outside, sizeof(outside), "%s/outside-shard",
                             base) < (int)sizeof(outside) &&
                    rename(shard, outside) == 0 &&
                    symlink("../../outside-shard", shard) == 0;
    FC_CHECK("export linked shard fixture is prepared", prepared);
    if (!prepared)
        return failures;
    bool refused = !vcs_fastobj_carrier_export(linked, store, root, stats,
                                               err, err_cap);
    FC_CHECK("export refuses a linked cache shard",
             refused && strstr(err, "linked cache shard"));
    bool restored = unlink(shard) == 0 &&
                    rename(outside, shard) == 0;
    FC_CHECK("same shard as real directory exports",
             restored && vcs_fastobj_carrier_export(linked, store, root,
                                                    stats, err, err_cap));
    return failures;
}

static bool fcw_linked_admit_paths(const char *base, const char *key,
                                   char dest[4096], char objects[4096],
                                   char shard[4096], char outside[4096],
                                   char outside_obj[4096],
                                   char outside_side[4096])
{
    return snprintf(dest, 4096, "%s/linked-admit", base) < 4096 &&
           snprintf(objects, 4096, "%s/objects", dest) < 4096 &&
           snprintf(shard, 4096, "%s/%.2s", objects, key) < 4096 &&
           snprintf(outside, 4096, "%s/outside-admit-shard", base) < 4096 &&
           snprintf(outside_obj, 4096, "%s/%s.o", outside, key + 2) < 4096 &&
           snprintf(outside_side, 4096, "%s/%s.json", outside,
                    key + 2) < 4096;
}

static int fcw_linked_admit_shard_refusal(
    const char *base, const char *key, struct vcs_package_store *store,
    const uint8_t root[32], char *err, size_t err_cap)
{
    int failures = 0;
    char dest[4096], objects[4096], shard[4096], outside[4096];
    char outside_obj[4096], outside_side[4096];
    bool prepared = fcw_linked_admit_paths(base, key, dest, objects, shard,
                                            outside, outside_obj,
                                            outside_side) &&
                    fcw_rm_rf(dest) && fcw_rm_rf(outside) &&
                    fcw_mkdir_p(objects) && mkdir(outside, 0700) == 0 &&
                    symlink("../../outside-admit-shard", shard) == 0;
    FC_CHECK("admit linked shard fixture is prepared", prepared);
    if (!prepared)
        return failures;
    struct vcs_fastobj_carrier_stats stats;
    bool refused = !vcs_fastobj_carrier_admit(dest, store, root, &stats,
                                              err, err_cap);
    struct stat st;
    bool outside_clean = lstat(outside_obj, &st) != 0 && errno == ENOENT &&
                         lstat(outside_side, &st) != 0 && errno == ENOENT;
    FC_CHECK("admit refuses a linked destination shard without outside writes",
             refused && outside_clean);
    bool restored = unlink(shard) == 0 && mkdir(shard, 0700) == 0;
    FC_CHECK("same destination as real shard admits",
             restored && vcs_fastobj_carrier_admit(dest, store, root,
                                                   &stats, err, err_cap));
    return failures;
}

static int fcw_empty_export_regression(void)
{
    int failures = 0;
    char base[PATH_MAX] = "", empty_cache[PATH_MAX], empty_objects[PATH_MAX];
    char store_dir[PATH_MAX], err[512] = "";
    uint8_t root[32] = {0};
    struct vcs_fastobj_carrier_stats stats = {0};
    struct vcs_package_store *store = NULL;
    bool owned = test_mkdtemp(base, sizeof(base), "fastobj_empty_export") != NULL;
    FC_CHECK("empty carrier scratch prepared", owned);
    if (!owned) return failures;
    int ec = snprintf(empty_cache, sizeof(empty_cache), "%s/empty-export", base);
    int eo = snprintf(empty_objects, sizeof(empty_objects),
                      "%s/empty-export/objects", base);
    int sd = snprintf(store_dir, sizeof(store_dir), "%s/store", base);
    bool ready = ec > 0 && (size_t)ec < sizeof(empty_cache) &&
                 eo > 0 && (size_t)eo < sizeof(empty_objects) &&
                 sd > 0 && (size_t)sd < sizeof(store_dir) &&
                 fcw_mkdir_p(empty_objects);
    if (ready)
        store = vcs_package_store_open(store_dir,
                                       VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    FC_CHECK("empty carrier fixture prepared", store != NULL);
    if (store) {
        FC_CHECK("empty cache export retains no-entry refusal",
                 !vcs_fastobj_carrier_export(empty_cache, store, root,
                                             &stats, err, sizeof(err)) &&
                 strstr(err, "holds no entries") != NULL);
        vcs_package_store_close(store);
    }
    FC_CHECK("empty carrier fixture removed", test_rm_rf_recursive(base) == 0);
    return failures;
}

#if defined(__linux__)
struct fcw_disk {
    uint64_t file_bytes;
    uint64_t directory_bytes;
    uint32_t files;
    size_t unique;
    dev_t devices[4];
    ino_t inodes[4];
};

static bool fcw_disk_file(struct fcw_disk *disk, const struct stat *st)
{
    disk->files++;
    for (size_t i = 0; i < disk->unique; i++)
        if (disk->devices[i] == st->st_dev && disk->inodes[i] == st->st_ino)
            return true;
    if (disk->unique == 4u)
        return false;
    disk->devices[disk->unique] = st->st_dev;
    disk->inodes[disk->unique++] = st->st_ino;
    disk->file_bytes += (uint64_t)st->st_blocks * 512u;
    return true;
}

/* Only the newly created crash fixture is traversed, at three levels. */
static bool fcw_crash_disk(const char *path, unsigned depth,
                            struct fcw_disk *disk)
{
    struct stat st;
    if (depth > 3u || lstat(path, &st) != 0 || !S_ISDIR(st.st_mode))
        return false;
    disk->directory_bytes += (uint64_t)st.st_blocks * 512u;
    DIR *dir = opendir(path);
    if (!dir)
        return false;
    bool ok = true;
    struct dirent *entry;
    while (ok && (entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        char child[4096];
        ok = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) <
                 (int)sizeof(child) && lstat(child, &st) == 0;
        if (ok && S_ISDIR(st.st_mode))
            ok = fcw_crash_disk(child, depth + 1u, disk);
        else if (ok && S_ISREG(st.st_mode))
            ok = fcw_disk_file(disk, &st);
        else {
            ok = false;
        }
    }
    return closedir(dir) == 0 && ok;
}

static bool fcw_same_inode(int fd, int dir, const char *name)
{
    struct stat opened, linked;
    return fstat(fd, &opened) == 0 &&
        fstatat(dir, name, &linked, AT_SYMLINK_NOFOLLOW) == 0 &&
        opened.st_ino == linked.st_ino && opened.st_dev == linked.st_dev;
}

static bool fcw_anonymous_support(const char *cache)
{
    int dir = open(cache, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0)
        return false;
    int fd = openat(dir, ".", O_TMPFILE | O_WRONLY | O_CLOEXEC, 0600);
    char source[128];
    bool ok = fd >= 0 && write(fd, "exact", 5u) == 5 && fsync(fd) == 0 &&
        platform_fd_path(source, sizeof(source), fd, NULL) &&
        linkat(AT_FDCWD, source, dir, "support", AT_SYMLINK_FOLLOW) == 0 &&
        fcw_same_inode(fd, dir, "support");
    if (ok) {
        errno = 0;
        ok = linkat(AT_FDCWD, source, dir, "support", AT_SYMLINK_FOLLOW) == -1 &&
             errno == EEXIST;
    }
    if (unlinkat(dir, "support", 0) != 0)
        ok = false;
    if (fd >= 0 && close(fd) != 0)
        ok = false;
    return close(dir) == 0 && ok;
}

/* RLIMIT_FSIZE kills the actual admit after one byte reaches its staging
 * inode, before either object or sidecar can be published. */
static bool fcw_crash_admit(const char *cache, struct vcs_package_store *store,
                             const uint8_t root[32])
{
    pid_t child = fork();
    if (child < 0)
        return false;
    if (child == 0) {
        (void)alarm(10u);
        struct rlimit file_limit = {1u, 1u}, core_limit = {0u, 0u};
        if (signal(SIGXFSZ, SIG_DFL) == SIG_ERR ||
            setrlimit(RLIMIT_CORE, &core_limit) != 0 ||
            setrlimit(RLIMIT_FSIZE, &file_limit) != 0)
            _exit(2);
        struct vcs_fastobj_carrier_stats stats;
        char err[256];
        bool admitted = vcs_fastobj_carrier_admit(cache, store, root, &stats,
                                                  err, sizeof(err));
        _exit(admitted ? 3 : 4);
    }
    int status = 0;
    return waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
           WTERMSIG(status) == SIGXFSZ;
}

static bool fcw_wait_child(pid_t child, int *status)
{
    pid_t result;
    do {
        result = waitpid(child, status, 0);
    } while (result < 0 && errno == EINTR);
    return result == child;
}

enum fcw_trace_event { FCW_TRACE_ERROR, FCW_TRACE_EXIT,
                       FCW_TRACE_WAIT, FCW_TRACE_PUBLISHED };

static enum fcw_trace_event fcw_publication_step(pid_t child, bool *publishing)
{
    int status = 0;
    if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) != 0)
        return FCW_TRACE_ERROR;
    if (!fcw_wait_child(child, &status) || !WIFSTOPPED(status))
        return FCW_TRACE_EXIT;
    struct ptrace_syscall_info info = {0};
    if (WSTOPSIG(status) != (SIGTRAP | 0x80) ||
        ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(info), &info) < 0)
        return FCW_TRACE_ERROR;
    if (info.op == PTRACE_SYSCALL_INFO_ENTRY)
        *publishing = info.entry.nr == SYS_linkat;
    if (info.op == PTRACE_SYSCALL_INFO_EXIT && *publishing &&
        info.exit.rval == 0)
        return FCW_TRACE_PUBLISHED;
    return FCW_TRACE_WAIT;
}

static bool fcw_kill_child(pid_t child)
{
    int status = 0;
    bool killed = kill(child, SIGKILL) == 0;
    bool reaped = fcw_wait_child(child, &status);
    return killed && reaped && WIFSIGNALED(status) &&
           WTERMSIG(status) == SIGKILL;
}

static bool fcw_stop_after_publication(pid_t child)
{
    int status = 0;
    bool stopped = fcw_wait_child(child, &status) && WIFSTOPPED(status);
    bool alive = stopped, publishing = false, published = false;
    if (stopped)
        stopped = ptrace(PTRACE_SETOPTIONS, child, NULL,
                          (void *)(uintptr_t)PTRACE_O_TRACESYSGOOD) == 0;
    for (unsigned step = 0; stopped && step < 10000u; step++) {
        enum fcw_trace_event event = fcw_publication_step(child, &publishing);
        if (event == FCW_TRACE_EXIT) {
            alive = false;
            break;
        }
        if (event == FCW_TRACE_ERROR || event == FCW_TRACE_PUBLISHED) {
            published = event == FCW_TRACE_PUBLISHED;
            break;
        }
    }
    if (alive)
        return fcw_kill_child(child) && published;
    return false;
}

static bool fcw_crash_after_object(const char *cache,
                                   struct vcs_package_store *store,
                                   const uint8_t root[32])
{
    pid_t child = fork();
    if (child < 0)
        return false;
    if (child == 0) {
        (void)alarm(10u);
        struct rlimit core_limit = {0u, 0u};
        if (setrlimit(RLIMIT_CORE, &core_limit) != 0 ||
            ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0 || raise(SIGSTOP) != 0)
            _exit(2);
        struct vcs_fastobj_carrier_stats stats;
        char err[256];
        bool admitted = vcs_fastobj_carrier_admit(cache, store, root, &stats,
                                                  err, sizeof(err));
        _exit(admitted ? 3 : 4);
    }
    return fcw_stop_after_publication(child);
}

#endif

static bool fcw_exact_retry(const char *cache, struct vcs_package_store *store,
                            const uint8_t root[32])
{
    struct vcs_fastobj_carrier_stats stats;
    char err[256];
    uint8_t round_trip[32];
    return vcs_fastobj_carrier_admit(cache, store, root, &stats, err,
                                    sizeof(err)) &&
           vcs_fastobj_carrier_admit(cache, store, root, &stats, err,
                                    sizeof(err)) &&
           vcs_fastobj_carrier_export(cache, store, round_trip, &stats, err,
                                     sizeof(err)) &&
           memcmp(root, round_trip, sizeof(round_trip)) == 0;
}

struct fcw_partial_paths {
    char object[4096], sidecar[4096], outside[4096];
};

static bool fcw_partial_paths_init(const char *cache,
                                   struct fcw_partial_paths *paths)
{
    char key[65];
    return fcw_first_entry(cache, key) &&
        vcs_fastobj_cache_paths(cache, key, paths->object, sizeof(paths->object),
                                paths->sidecar, sizeof(paths->sidecar)) &&
        snprintf(paths->outside, sizeof(paths->outside), "%s/outside", cache) <
            (int)sizeof(paths->outside);
}

static bool fcw_bytes_equal(const char *path, const char *expected, size_t size)
{
    size_t len = 0;
    uint8_t *bytes = fcw_read_file(path, size, &len);
    bool equal = bytes && len == size && memcmp(bytes, expected, size) == 0;
    free(bytes);
    return equal;
}

static int fcw_divergent_object_refusal(const struct fcw_partial_paths *paths,
                                        struct vcs_package_store *store,
                                        const uint8_t root[32],
                                        const char *cache)
{
    int failures = 0;
    char err[256];
    struct vcs_fastobj_carrier_stats stats;
    bool ready = unlink(paths->sidecar) == 0 &&
        chmod(paths->object, 0600) == 0 &&
        fcw_write_file(paths->object, "divergent", 9u);
    FC_CHECK("divergent lone object refuses without sidecar publication",
             ready && !vcs_fastobj_carrier_admit(cache, store, root, &stats,
                                                err, sizeof(err)) &&
             !fcw_exists(paths->sidecar) &&
             fcw_bytes_equal(paths->object, "divergent", 9u));
    return failures;
}

static int fcw_linked_partial_refusal(const struct fcw_partial_paths *paths,
                                       struct vcs_package_store *store,
                                       const uint8_t root[32], const char *cache)
{
    int failures = 0;
    char err[256];
    struct vcs_fastobj_carrier_stats stats;
    bool ready = unlink(paths->object) == 0 &&
        fcw_write_file(paths->outside, "outside", 7u) &&
        symlink(paths->outside, paths->object) == 0;
    FC_CHECK("linked lone object refuses without sidecar publication",
             ready && !vcs_fastobj_carrier_admit(cache, store, root, &stats,
                                                err, sizeof(err)) &&
             !fcw_exists(paths->sidecar));
    FC_CHECK("linked object refusal preserves outside bytes",
             ready && fcw_bytes_equal(paths->outside, "outside", 7u));
    return failures;
}

static int fcw_sidecar_only_refusal(const struct fcw_partial_paths *paths,
                                    struct vcs_package_store *store,
                                    const uint8_t root[32], const char *cache)
{
    int failures = 0;
    char err[256];
    struct vcs_fastobj_carrier_stats stats;
    bool ready = unlink(paths->object) == 0 &&
                 fcw_write_file(paths->sidecar, "sidecar-only", 12u);
    FC_CHECK("sidecar-only entry refuses without object publication",
             ready && !vcs_fastobj_carrier_admit(cache, store, root, &stats,
                                                err, sizeof(err)) &&
             !fcw_exists(paths->object));
    return failures;
}

static int fcw_partial_pair_refusals(const char *cache,
                                      struct vcs_package_store *store,
                                      const uint8_t root[32])
{
    struct fcw_partial_paths paths;
    if (!fcw_partial_paths_init(cache, &paths))
        return 1;
    int failures = fcw_divergent_object_refusal(&paths, store, root, cache);
    failures += fcw_linked_partial_refusal(&paths, store, root, cache);
    failures += fcw_sidecar_only_refusal(&paths, store, root, cache);
    return failures;
}

/* This process-independent recovery path is exercised on every POSIX host;
 * removing an admitted sidecar supplies the exact incomplete-pair precondition. */
static int fcw_portable_partial_retry(const char *base,
                                      struct vcs_package_store *store,
                                      const uint8_t root[32])
{
    int failures = 0;
    char cache[4096], key[65], object[4096], sidecar[4096];
    bool ready = snprintf(cache, sizeof(cache), "%s/partial-retry", base) <
                    (int)sizeof(cache) && fcw_exact_retry(cache, store, root) &&
        fcw_first_entry(cache, key) &&
        vcs_fastobj_cache_paths(cache, key, object, sizeof(object),
                                sidecar, sizeof(sidecar)) &&
        unlink(sidecar) == 0;
    FC_CHECK("portable exact-object/missing-sidecar fixture", ready);
    bool recovered = ready && fcw_exact_retry(cache, store, root);
    FC_CHECK("portable missing-sidecar retry completes exact/idempotent pair",
             recovered);
    if (recovered)
        failures += fcw_partial_pair_refusals(cache, store, root);
    return failures;
}

#if defined(__linux__)
static int fcw_publication_crash_case(const char *base,
                                      struct vcs_package_store *store,
                                      const uint8_t root[32])
{
    int failures = 0;
    char cache[4096];
    bool ready = snprintf(cache, sizeof(cache), "%s/object-only-admit", base) <
                    (int)sizeof(cache) && fcw_mkdir_p(cache);
    FC_CHECK("actual admit killed after first object publication",
             ready && fcw_crash_after_object(cache, store, root));
    struct fcw_disk after = {0};
    bool counted = ready && fcw_crash_disk(cache, 0, &after);
    printf("  fastobj_carrier: first-publication allocated file bytes=%llu "
           "directory bytes=%llu files=%u\n",
           (unsigned long long)after.file_bytes,
           (unsigned long long)after.directory_bytes, after.files);
    FC_CHECK("first publication retains exactly one allocated object",
             counted && after.files == 1u && after.file_bytes > 0);
    FC_CHECK("object-only retry completes exact pair without overwrite",
             ready && fcw_exact_retry(cache, store, root));
    return failures;
}

static int fcw_anonymous_crash_refusal(const char *base,
                                       struct vcs_package_store *store,
                                       const uint8_t root[32])
{
    int failures = 0;
    char cache[4096];
    bool ready = snprintf(cache, sizeof(cache), "%s/crash-admit", base) <
                     (int)sizeof(cache) && fcw_mkdir_p(cache);
    FC_CHECK("unprivileged exact-inode anonymous publication/no-overwrite",
             ready && fcw_anonymous_support(cache));
    if (!ready)
        return failures + 1;
    struct fcw_disk before = {0}, after = {0};
    bool counted = fcw_crash_disk(cache, 0, &before);
    FC_CHECK("actual admit killed during staging write",
             fcw_crash_admit(cache, store, root));
    counted = fcw_crash_disk(cache, 0, &after) && counted;
    printf("  fastobj_carrier: crash allocated file bytes=%llu->%llu "
           "directory bytes=%llu->%llu\n",
           (unsigned long long)before.file_bytes,
           (unsigned long long)after.file_bytes,
           (unsigned long long)before.directory_bytes,
           (unsigned long long)after.directory_bytes);
    FC_CHECK("death retains zero staging files/allocated file bytes",
             counted && before.files == 0 && after.files == 0 &&
             before.file_bytes == 0 && after.file_bytes == 0);
    FC_CHECK("staging death retry is exact and idempotent",
             fcw_exact_retry(cache, store, root));
    failures += fcw_publication_crash_case(base, store, root);
    return failures;
}
#endif

/* Shared state for the platform arm: every scratch path, root, store and
 * receipt that more than one leg reads. The legs run in the original order;
 * a leg sets stop where the original goto done fired, and fatal where the
 * original returned before cleanup. */
struct fcw_arm {
    bool stop;
    bool fatal;
    bool testless_ready;
    bool finding_ready;
    char err[512];
    char worker[4096];
    char base[4096];
    char pkg[4096], cacheA[4096], cacheB[4096], emit1[4096], emit2[4096],
         recipe_path[4096], dirA[4096], dirB[4096], dirC[4096], dirD[4096],
         dirR[4096];
    char root_hex[65], lock_hex[65], key[65];
    struct pubkey pk;
    struct vcs_package_prepared prep, prepT, prepF;
    struct fcw_build_result run1, run2, tref, tok;
    struct vcs_fastobj_carrier_stats stA, stC, stF, stAd, stD, stRef;
    uint8_t rootA[32], rootC[32], rootD[32], rootL[32];
    struct vcs_package_store *nodeA, *nodeB, *nodeC, *nodeD, *storeR;
    size_t r1_len, r2_len, rT_len, rF_len;
    uint8_t *r1, *r2, *rT, *rF;
    char pkgT[4096], recipeT_path[4096], emitT1[4096], emitT2[4096],
         cacheT[4096], rootT_hex[65], lockT_hex[65];
    char pkgF[4096], recipeF_path[4096], emitF[4096], cacheF[4096],
         rootF_hex[65], lockF_hex[65];
};

static int fcw_arm_setup(struct fcw_arm *a)
{
    int failures = 0;
    /* The confined worker ships beside this binary — never from PATH. */
    bool have_worker = fcw_worker_path(a->worker, sizeof(a->worker));
    FC_CHECK("package verifier beside the test binary (make dev-bin)",
             have_worker);
    char cwd[3072];
    bool base_ok = getcwd(cwd, sizeof(cwd)) != NULL &&
        snprintf(a->base, sizeof(a->base), "%s/test-tmp/fastobj_carrier_%ld",
                 cwd, (long)getpid()) < (int)sizeof(a->base);
    if (!base_ok || !have_worker) {
        printf("fastobj_carrier: FAIL (setup)\n");
        a->fatal = true;
        return failures;
    }
    (void)fcw_rm_rf(a->base);
    if (!fcw_mkdir_p(a->base)) {
        printf("fastobj_carrier: FAIL (scratch %s)\n", a->base);
        a->fatal = true;
    }
    return failures;
}

static int fcw_arm_layout(struct fcw_arm *a)
{
    int failures = 0;
    bool paths_ok =
        snprintf(a->pkg, sizeof(a->pkg), "%s/pkg", a->base) < (int)sizeof(a->pkg) &&
        snprintf(a->cacheA, sizeof(a->cacheA), "%s/cacheA", a->base) <
            (int)sizeof(a->cacheA) &&
        snprintf(a->cacheB, sizeof(a->cacheB), "%s/cacheB", a->base) <
            (int)sizeof(a->cacheB) &&
        snprintf(a->emit1, sizeof(a->emit1), "%s/emit1", a->base) <
            (int)sizeof(a->emit1) &&
        snprintf(a->emit2, sizeof(a->emit2), "%s/emit2", a->base) <
            (int)sizeof(a->emit2) &&
        snprintf(a->recipe_path, sizeof(a->recipe_path), "%s/recipe.wire", a->base) <
            (int)sizeof(a->recipe_path) &&
        snprintf(a->dirA, sizeof(a->dirA), "%s/nodeA", a->base) < (int)sizeof(a->dirA) &&
        snprintf(a->dirB, sizeof(a->dirB), "%s/nodeB", a->base) < (int)sizeof(a->dirB) &&
        snprintf(a->dirC, sizeof(a->dirC), "%s/nodeC", a->base) < (int)sizeof(a->dirC) &&
        snprintf(a->dirD, sizeof(a->dirD), "%s/nodeD", a->base) < (int)sizeof(a->dirD) &&
        snprintf(a->dirR, sizeof(a->dirR), "%s/storeR", a->base) < (int)sizeof(a->dirR);
    FC_CHECK("scratch paths laid out", paths_ok);
    if (!paths_ok)
        a->stop = true;
    return failures;
}

static int fcw_arm_prepare(struct fcw_arm *a)
{
    int failures = 0;
    /* 1. prepare the tiny-lines fixture (contexts/commons/modules/vcs only — the candidate
     * proof action needs no signed release). */
    FC_CHECK("tiny-lines fixture copied to scratch",
             fcw_copy_tree("tests/harness/fixtures/zcode/tiny-lines", a->pkg));
    struct vcs_package_prepare_options opts;
    memset(&opts, 0, sizeof(opts));
    opts.dir = a->pkg;
    /* The release layer validates the publisher pubkey as a compressed
     * curve point, so derive a real one (the test_zcode_add idiom). */
    struct privkey sk;
    memset(sk.vch, 0x11, 32);
    sk.fValid = true;
    sk.fCompressed = true;
    bool have_pk = privkey_get_pubkey(&sk, &a->pk);
    FC_CHECK("publisher pubkey derived for prepare", have_pk);
    if (!have_pk) {
        a->stop = true;
        return failures;
    }
    memcpy(opts.publisher_pubkey, a->pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    opts.publisher_sequence = 1;
    char prep_detail[512] = "";
    enum vcs_package_prepare_error prc =
        vcs_package_prepare(&opts, &a->prep, prep_detail, sizeof(prep_detail));
    FC_CHECK("package prepared (root, recipe, lock derived)",
             prc == VCS_PACKAGE_PREPARE_OK);
    if (prc != VCS_PACKAGE_PREPARE_OK)
        printf("    prepare: %s\n", prep_detail);
    zcl_hex_encode(a->prep.package_root, 32, a->root_hex);
    zcl_hex_encode(a->prep.lock_root, 32, a->lock_hex);
    FC_CHECK("recipe wire written for the worker",
             prc == VCS_PACKAGE_PREPARE_OK &&
                 fcw_write_file(a->recipe_path, a->prep.recipe_wire,
                                a->prep.recipe_wire_len));
    if (prc != VCS_PACKAGE_PREPARE_OK)
        a->stop = true;
    return failures;
}

static int fcw_arm_build_cold(struct fcw_arm *a)
{
    int failures = 0;
    /* 2. candidate build #1 on a COLD cacheA: the compile really runs. */
    fcw_candidate_build(a->worker, a->root_hex, a->pkg, a->recipe_path, a->emit1,
                        a->lock_hex, a->cacheA, false, false, &a->run1);
    FC_CHECK("candidate build #1 (cold cacheA) succeeded", a->run1.ok);
    if (!a->run1.ok) {
        printf("    build #1 exit %d: %.200s\n", a->run1.exit_code,
               a->run1.first_line);
        printf("    build #1 final: %.240s\n", a->run1.last_line);
    }
    FC_CHECK("build #1 compiled both library and test objects",
             a->run1.ok && a->run1.misses == 2u && a->run1.hits == 0u);
    printf("    build #1: hits=%llu misses=%llu\n", a->run1.hits, a->run1.misses);
    if (!a->run1.ok)
        a->stop = true;
    return failures;
}

static int fcw_arm_export_a(struct fcw_arm *a)
{
    int failures = 0;
    /* 3. export cacheA into store nodeA as ONE content.v2 carrier. */
    a->nodeA = vcs_package_store_open(a->dirA, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    bool expA = a->nodeA != NULL && vcs_fastobj_carrier_export(
                                        a->cacheA, a->nodeA, a->rootA, &a->stA, a->err,
                                        sizeof(a->err));
    FC_CHECK("cacheA exported as one content.v2 carrier", expA);
    if (!expA)
        printf("    export: %s\n", a->err);
    FC_CHECK("carrier entries == build #1 misses",
             expA && a->stA.entries == (uint32_t)a->run1.misses);
    FC_CHECK("carrier files are object+sidecar pairs",
             expA && a->stA.files == 2u * a->stA.entries);
    FC_CHECK("carrier carries real object bytes",
             expA && a->stA.object_bytes > 0u);
    if (!expA)
        a->stop = true;
    return failures;
}

static int fcw_arm_first(struct fcw_arm *a)
{
    int failures = fcw_arm_layout(a);
    if (a->stop)
        return failures;
    failures += fcw_arm_prepare(a);
    if (a->stop)
        return failures;
    failures += fcw_arm_build_cold(a);
    if (a->stop)
        return failures;
    return failures + fcw_arm_export_a(a);
}

static int fcw_arm_shape_a(struct fcw_arm *a)
{
    int failures = 0;
    /* 4. the carrier has a public shape: a -packagehost=1 node may announce
     *    and serve it; the serve-time proof is the consumer's admit proof. */
    struct vcs_package_public_verdict shape_v;
    enum vcs_package_public_shape pub =
        vcs_package_public_shape_classify(a->nodeA, a->rootA, &shape_v);
    FC_CHECK("exported carrier classifies as fastobj-carrier",
             pub == VCS_PACKAGE_PUBLIC_FASTOBJ_CARRIER);
    FC_CHECK("the carrier rule is its shape string",
             shape_v.rule != NULL &&
                 strcmp(shape_v.rule,
                        vcs_package_public_shape_string(pub)) == 0);
    FC_CHECK("fastobj carrier is not licensed content",
             !vcs_package_public_shape_licensed(pub));
    FC_CHECK("read-only carrier verify passes on the exporter's store",
             vcs_fastobj_carrier_verify(a->nodeA, a->rootA, a->err, sizeof(a->err)));
    return failures;
}

static int fcw_arm_reexport_c(struct fcw_arm *a)
{
    int failures = 0;
    /* 5. re-export into a THIRD store: the root must not move. */
    a->nodeC = vcs_package_store_open(a->dirC, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    bool expC = a->nodeC != NULL && vcs_fastobj_carrier_export(
                                         a->cacheA, a->nodeC, a->rootC, &a->stC, a->err,
                                         sizeof(a->err));
    FC_CHECK("re-export into a third store succeeded", expC);
    if (!expC)
        printf("    re-export: %s\n", a->err);
    FC_CHECK("the carrier root is deterministic (same cache, same root)",
             expC && memcmp(a->rootA, a->rootC, 32) == 0);
    return failures;
}

static int fcw_arm_fetch_admit(struct fcw_arm *a)
{
    int failures = 0;
    /* 6. fetch store-to-store: the offline stand-in for the swarm wire. */
    a->nodeB = vcs_package_store_open(a->dirB, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    bool fetched = a->nodeB != NULL && vcs_fastobj_carrier_fetch(
                                           a->nodeB, a->nodeA, a->rootA, &a->stF, a->err,
                                           sizeof(a->err));
    FC_CHECK("carrier fetched store-to-store into nodeB", fetched);
    if (!fetched)
        printf("    fetch: %s\n", a->err);
    FC_CHECK("fetched carrier carries the same entries",
             fetched && a->stF.entries == a->stA.entries);
    failures += fcw_fetch_resume(a->nodeB, a->nodeA, a->rootA, a->dirB, a->dirA, fetched);
    /* 7. admit nodeB's carrier into a FRESH cacheB. */
    bool admitted = fetched && vcs_fastobj_carrier_admit(
                                   a->cacheB, a->nodeB, a->rootA, &a->stAd, a->err,
                                   sizeof(a->err));
    FC_CHECK("carrier admitted into a fresh cacheB", admitted);
    if (!admitted)
        printf("    admit: %s\n", a->err);
    FC_CHECK("cacheB holds every carried entry",
             admitted && a->stAd.entries == a->stA.entries);
    return failures;
}

static int fcw_arm_reexport_d(struct fcw_arm *a)
{
    int failures = 0;
    /* 8. re-export cacheB into a FOURTH store: same root again. */
    a->nodeD = vcs_package_store_open(a->dirD, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    bool expD = a->nodeD != NULL && vcs_fastobj_carrier_export(
                                        a->cacheB, a->nodeD, a->rootD, &a->stD, a->err,
                                        sizeof(a->err));
    FC_CHECK("cacheB re-exported into a fourth store", expD);
    if (!expD)
        printf("    re-export cacheB: %s\n", a->err);
    FC_CHECK("round-trip root identical (cacheB bytes == cacheA bytes)",
             expD && memcmp(a->rootA, a->rootD, 32) == 0);
    return failures;
}

static int fcw_arm_build_warm(struct fcw_arm *a)
{
    int failures = 0;
    /* 9. Adding dependency-plan evidence must reuse the same object digest. */
    fcw_candidate_build(a->worker, a->root_hex, a->pkg, a->recipe_path, a->emit2,
                        a->lock_hex, a->cacheB, false, true, &a->run2);
    FC_CHECK("candidate build #2 (warm cacheB) succeeded", a->run2.ok);
    if (!a->run2.ok)
        printf("    build #2 exit %d: %.200s\n", a->run2.exit_code,
               a->run2.first_line);
    printf("    build #2: hits=%llu misses=%llu\n", a->run2.hits, a->run2.misses);
    FC_CHECK("build #2 has no eligible object misses",
             a->run2.ok && a->run2.misses == 0u);
    FC_CHECK("build #2 hit every entry build #1 missed",
             a->run2.ok && a->run2.hits == a->run1.misses);
    failures += fcw_check_perf(&a->run1, &a->run2);
    return failures;
}

static int fcw_arm_receipts_emit(struct fcw_arm *a)
{
    int failures = 0;
    /* 10. the ZCLBLD receipts are byte-identical. */
    char report1[4096], report2[4096];
    bool got_reports =
        snprintf(report1, sizeof(report1), "%s/build-report", a->emit1) <
            (int)sizeof(report1) &&
        snprintf(report2, sizeof(report2), "%s/build-report", a->emit2) <
            (int)sizeof(report2);
    if (got_reports) {
        a->r1 = fcw_read_file(report1, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES,
                              &a->r1_len);
        a->r2 = fcw_read_file(report2, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES,
                              &a->r2_len);
    }
    FC_CHECK("both ZCLBLD build-reports emitted", a->r1 != NULL && a->r2 != NULL);
    FC_CHECK("build-report #2 is byte-identical to #1",
             a->r1 && a->r2 && a->r1_len == a->r2_len &&
                 memcmp(a->r1, a->r2, a->r1_len) == 0);
    return failures;
}

static int fcw_arm_receipts_ids(struct fcw_arm *a)
{
    int failures = 0;
    struct vcs_package_build_receipt rec1, rec2;
    uint8_t id1[32] = {0}, id2[32] = {0};
    bool ids_ok = a->r1 && a->r2 &&
        vcs_package_build_parse(a->r1, a->r1_len, &rec1) == VCS_PACKAGE_BUILD_OK &&
        vcs_package_build_parse(a->r2, a->r2_len, &rec2) == VCS_PACKAGE_BUILD_OK &&
        vcs_package_build_id(&rec1, id1) == VCS_PACKAGE_BUILD_OK &&
        vcs_package_build_id(&rec2, id2) == VCS_PACKAGE_BUILD_OK;
    FC_CHECK("both receipts parse and hash to the same id",
             ids_ok && memcmp(id1, id2, 32) == 0);
    /* 10. receipt #1 really ran the fixture's tests and its flags string
     * claims "clean" (both sanitizer outcomes PASS). */
    FC_CHECK("tested standard receipt really ran its tests",
             ids_ok && rec1.test_ran &&
                 rec1.result_class == VCS_PACKAGE_BUILD_RESULT_TEST_PASS);
    FC_CHECK("tested standard receipt flags still claim asan,ubsan=clean",
             ids_ok && strstr(rec1.flags, "asan,ubsan=clean") != NULL);
    return failures;
}

static int fcw_arm_bypass_legs(struct fcw_arm *a)
{
    int failures = 0;
#if defined(__linux__)
    failures += fcw_asm_bypass(a->base, a->worker, &a->pk, false);
    failures += fcw_attribute_bypass(a->base, a->worker, &a->pk);
    failures += fcw_test_cache_failure(a->base, a->worker, &a->pk);
    failures += fcw_program_cache_probe(a->base, a->worker, &a->pk);
#elif defined(__APPLE__)
    failures += fcw_asm_bypass(a->base, a->worker, &a->pk, false);
    failures += fcw_apple_attribute_spellings(a->base, a->worker, &a->pk);
#endif
    return failures;
}

static int fcw_arm_testless_prepare(struct fcw_arm *a)
{
    int failures = 0;
    /* 11. testless standard-profile refusal: a copy without tests/ is
     * REFUSED with exit 6 in the evidence shape, and BUILDS with
     * --allow-testless-standard, recording test_ran=false,
     * result_class=BUILD_PASS. */
    char testsT[4096];
    bool pathsT_ok =
        snprintf(a->pkgT, sizeof(a->pkgT), "%s/pkgT", a->base) < (int)sizeof(a->pkgT) &&
        snprintf(a->recipeT_path, sizeof(a->recipeT_path), "%s/recipeT.wire",
                 a->base) < (int)sizeof(a->recipeT_path) &&
        snprintf(a->emitT1, sizeof(a->emitT1), "%s/emitT1", a->base) <
            (int)sizeof(a->emitT1) &&
        snprintf(a->emitT2, sizeof(a->emitT2), "%s/emitT2", a->base) <
            (int)sizeof(a->emitT2) &&
        snprintf(a->cacheT, sizeof(a->cacheT), "%s/cacheT", a->base) <
            (int)sizeof(a->cacheT) &&
        snprintf(testsT, sizeof(testsT), "%s/tests", a->pkgT) <
            (int)sizeof(testsT);
    bool testless_ready = pathsT_ok &&
        fcw_copy_tree("tests/harness/fixtures/zcode/tiny-lines", a->pkgT) &&
        fcw_rm_rf(testsT);
    struct vcs_package_prepare_options optsT;
    memset(&optsT, 0, sizeof(optsT));
    optsT.dir = a->pkgT;
    memcpy(optsT.publisher_pubkey, a->pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    optsT.publisher_sequence = 1;
    char prepT_detail[512] = "";
    enum vcs_package_prepare_error prcT = VCS_PACKAGE_PREPARE_ERR_IO;
    if (testless_ready)
        prcT = vcs_package_prepare(&optsT, &a->prepT, prepT_detail,
                                   sizeof(prepT_detail));
    if (prcT == VCS_PACKAGE_PREPARE_OK) {
        zcl_hex_encode(a->prepT.package_root, 32, a->rootT_hex);
        zcl_hex_encode(a->prepT.lock_root, 32, a->lockT_hex);
    }
    testless_ready =
        testless_ready && prcT == VCS_PACKAGE_PREPARE_OK &&
        fcw_write_file(a->recipeT_path, a->prepT.recipe_wire,
                       a->prepT.recipe_wire_len);
    FC_CHECK("testless fixture variant (tests/ dropped) prepared",
             testless_ready);
    if (!testless_ready && prcT != VCS_PACKAGE_PREPARE_OK)
        printf("    prepare testless: %s\n", prepT_detail);
    a->testless_ready = testless_ready;
    return failures;
}

static int fcw_arm_testless_refuse_allow(struct fcw_arm *a)
{
    int failures = 0;
    memset(&a->tref, 0, sizeof(a->tref));
    memset(&a->tok, 0, sizeof(a->tok));
    fcw_candidate_build(a->worker, a->rootT_hex, a->pkgT, a->recipeT_path, a->emitT1,
                        a->lockT_hex, a->cacheT, false, false, &a->tref);
    FC_CHECK("evidence-shape standard run of a testless package "
             "refuses (exit 6 + refusal line)",
             a->tref.exit_code == 6 && a->tref.saw_refusal);
    if (!(a->tref.exit_code == 6 && a->tref.saw_refusal))
        printf("    testless refuse: exit %d: %.200s\n",
               a->tref.exit_code, a->tref.first_line);
    fcw_candidate_build(a->worker, a->rootT_hex, a->pkgT, a->recipeT_path, a->emitT2,
                        a->lockT_hex, a->cacheT, true, false, &a->tok);
    FC_CHECK("reproduce-shape standard run of a testless package "
             "builds", a->tok.ok);
    FC_CHECK("testless build reports no test processes",
             fcw_testless_perf(&a->tok));
    if (!a->tok.ok)
        printf("    testless allow: exit %d: %.200s\n", a->tok.exit_code,
               a->tok.first_line);
    return failures;
}

static int fcw_arm_testless_receipt(struct fcw_arm *a)
{
    int failures = 0;
    char reportT[4096];
    if (a->tok.ok &&
        snprintf(reportT, sizeof(reportT), "%s/build-report", a->emitT2) <
            (int)sizeof(reportT))
        a->rT = fcw_read_file(reportT, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES,
                              &a->rT_len);
    struct vcs_package_build_receipt recT;
    bool recT_ok =
        a->rT != NULL && vcs_package_build_parse(a->rT, a->rT_len, &recT) ==
                              VCS_PACKAGE_BUILD_OK;
    FC_CHECK("testless emit receipt parses", recT_ok);
    FC_CHECK("testless receipt records the honest facts (no test run, "
             "build-pass only)",
             recT_ok && !recT.test_ran &&
                 recT.result_class == VCS_PACKAGE_BUILD_RESULT_BUILD_PASS);
    FC_CHECK("testless receipt flags say asan,ubsan=not-run (never ran, "
             "never claimed clean)",
             recT_ok &&
                 strstr(recT.flags, "asan,ubsan=not-run") != NULL);
    FC_CHECK("testless receipt stays installable for reproduction",
             recT_ok && vcs_package_build_installable(&recT));
    return failures;
}

static int fcw_arm_finding_prepare(struct fcw_arm *a)
{
    int failures = 0;
    /* 12. a sanitizer finding on the reproduce track: the test reads freed
     * heap hidden in a second TU, so ASan reports it. With the opt-out flag
     * the build still EMITS an installable TEST_PASS receipt (evidence, not
     * a gate) whose flags say "findings", never "clean". */
    static const char uaf_test[] =
        "/* Deliberate heap-use-after-free: the plain run reads stale but\n"
        " * mapped bytes and exits 0; the ASan run reports and exits by the\n"
        " * marker code. Fixture for the flags-honesty leg only. The free\n"
        " * hides in uaf_helper.c so -Wuse-after-free cannot see it. */\n"
        "#include <stdlib.h>\n"
        "\n"
        "void fixture_uaf_free(void *p);\n"
        "\n"
        "int main(void)\n"
        "{\n"
        "    int *p = (int *)malloc(sizeof(*p));\n"
        "    if (!p)\n"
        "        return 1;\n"
        "    *p = 42;\n"
        "    fixture_uaf_free(p);\n"
        "    volatile int sink = *p;\n"
        "    (void)sink;\n"
        "    return 0;\n"
        "}\n";
    static const char uaf_helper[] =
        "/* Keeps free() out of the test TU's static-analysis reach. */\n"
        "#include <stdlib.h>\n"
        "\n"
        "void fixture_uaf_free(void *p)\n"
        "{\n"
        "    free(p);\n"
        "}\n";
    char testF_path[4096], helperF_path[4096];
    bool pathsF_ok =
        snprintf(a->pkgF, sizeof(a->pkgF), "%s/pkgF", a->base) < (int)sizeof(a->pkgF) &&
        snprintf(a->recipeF_path, sizeof(a->recipeF_path), "%s/recipeF.wire",
                 a->base) < (int)sizeof(a->recipeF_path) &&
        snprintf(a->emitF, sizeof(a->emitF), "%s/emitF", a->base) <
            (int)sizeof(a->emitF) &&
        snprintf(a->cacheF, sizeof(a->cacheF), "%s/cacheF", a->base) <
            (int)sizeof(a->cacheF) &&
        snprintf(testF_path, sizeof(testF_path),
                 "%s/tests/test_tiny_lines.c", a->pkgF) < (int)sizeof(testF_path) &&
        snprintf(helperF_path, sizeof(helperF_path),
                 "%s/tests/uaf_helper.c", a->pkgF) < (int)sizeof(helperF_path);
    struct vcs_package_prepare_options optsF;
    memset(&optsF, 0, sizeof(optsF));
    optsF.dir = a->pkgF;
    memcpy(optsF.publisher_pubkey, a->pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    optsF.publisher_sequence = 1;
    char prepF_detail[512] = "";
    enum vcs_package_prepare_error prcF = VCS_PACKAGE_PREPARE_ERR_IO;
    bool finding_ready = pathsF_ok &&
        fcw_copy_tree("tests/harness/fixtures/zcode/tiny-lines", a->pkgF) &&
        fcw_write_file(testF_path, (const uint8_t *)uaf_test,
                       sizeof(uaf_test) - 1u) &&
        fcw_write_file(helperF_path, (const uint8_t *)uaf_helper,
                       sizeof(uaf_helper) - 1u);
    if (finding_ready)
        prcF = vcs_package_prepare(&optsF, &a->prepF, prepF_detail,
                                   sizeof(prepF_detail));
    if (prcF == VCS_PACKAGE_PREPARE_OK) {
        zcl_hex_encode(a->prepF.package_root, 32, a->rootF_hex);
        zcl_hex_encode(a->prepF.lock_root, 32, a->lockF_hex);
    }
    finding_ready =
        finding_ready && prcF == VCS_PACKAGE_PREPARE_OK &&
        fcw_write_file(a->recipeF_path, a->prepF.recipe_wire,
                       a->prepF.recipe_wire_len);
    FC_CHECK("use-after-free fixture variant prepared", finding_ready);
    if (!finding_ready && prcF != VCS_PACKAGE_PREPARE_OK)
        printf("    prepare findings: %s\n", prepF_detail);
    a->finding_ready = finding_ready;
    return failures;
}

static int fcw_arm_finding_run(struct fcw_arm *a)
{
    int failures = 0;
    struct fcw_build_result frun;
    memset(&frun, 0, sizeof(frun));
    fcw_candidate_build(a->worker, a->rootF_hex, a->pkgF, a->recipeF_path, a->emitF,
                        a->lockF_hex, a->cacheF, true, false, &frun);
    FC_CHECK("reproduce-shape standard run with an ASan finding still "
             "emits (evidence, not a gate)", frun.ok);
    if (!frun.ok)
        printf("    findings run: exit %d: %.200s\n", frun.exit_code,
               frun.first_line);
    printf("    findings run tail: %.200s\n", frun.last_line);
    char reportF[4096];
    if (frun.ok &&
        snprintf(reportF, sizeof(reportF), "%s/build-report", a->emitF) <
            (int)sizeof(reportF))
        a->rF = fcw_read_file(reportF, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES,
                              &a->rF_len);
    return failures;
}

static int fcw_arm_finding_receipt(struct fcw_arm *a)
{
    int failures = 0;
    struct vcs_package_build_receipt recF;
    bool recF_ok =
        a->rF != NULL && vcs_package_build_parse(a->rF, a->rF_len, &recF) ==
                              VCS_PACKAGE_BUILD_OK;
    FC_CHECK("findings emit receipt parses", recF_ok);
    FC_CHECK("findings receipt flags say asan,ubsan=findings (never "
             "clean)",
             recF_ok &&
                 strstr(recF.flags, "asan,ubsan=findings") != NULL);
    FC_CHECK("findings receipt keeps the build+test verdict "
             "(test-pass, installable) — unchanged emit semantics",
             recF_ok && recF.test_ran &&
                 recF.result_class == VCS_PACKAGE_BUILD_RESULT_TEST_PASS &&
                 vcs_package_build_installable(&recF));
    return failures;
}

static int fcw_arm_refuse_torn(struct fcw_arm *a)
{
    int failures = 0;
    /* R1: a torn pair (sidecar deleted) refuses the WHOLE export. */
    char torn[4096];
    if (snprintf(torn, sizeof(torn), "%s/torn", a->base) <
        (int)sizeof(torn)) {
        (void)fcw_rm_rf(torn);
        if (fcw_copy_tree(a->cacheA, torn)) {
            char o[4096], s[4096];
            if (vcs_fastobj_cache_paths(torn, a->key, o, sizeof(o), s,
                                        sizeof(s)))
                (void)unlink(s);
            bool refused = !vcs_fastobj_carrier_export(
                torn, a->nodeA, a->rootL, &a->stRef, a->err, sizeof(a->err));
            FC_CHECK("export refuses a torn pair",
                     refused && strstr(a->err, "torn") != NULL);
            if (!(refused && strstr(a->err, "torn")))
                printf("    torn export: %s\n", a->err);
        } else {
            FC_CHECK("export refuses a torn pair", false);
        }
    }
    return failures;
}

static int fcw_arm_refuse_lying(struct fcw_arm *a)
{
    int failures = 0;
    /* R2: a sidecar whose object_sha3 lies about its object. */
    char lying[4096];
    if (snprintf(lying, sizeof(lying), "%s/lying", a->base) <
        (int)sizeof(lying)) {
        (void)fcw_rm_rf(lying);
        if (fcw_copy_tree(a->cacheA, lying)) {
            char o[4096], s[4096];
            size_t side_len = 0;
            uint8_t *side = NULL;
            if (vcs_fastobj_cache_paths(lying, a->key, o, sizeof(o), s,
                                        sizeof(s)) &&
                (side = fcw_read_file(s, VCS_FASTOBJ_SIDECAR_MAX_BYTES,
                                      &side_len)) != NULL) {
                const char *hit = fcw_find(side, side_len,
                                           "\"object_sha3\":\"");
                if (hit) {
                    char *hex = (char *)hit +
                                strlen("\"object_sha3\":\"");
                    hex[0] = hex[0] == '0' ? '1' : '0';
                }
                if (hit && fcw_write_file(s, side, side_len)) {
                    bool refused = !vcs_fastobj_carrier_export(
                        lying, a->nodeA, a->rootL, &a->stRef, a->err, sizeof(a->err));
                    FC_CHECK("export refuses a lying object_sha3",
                             refused && strstr(a->err, "does not hash") !=
                                           NULL);
                    if (!(refused &&
                          strstr(a->err, "does not hash")))
                        printf("    lying export: %s\n", a->err);
                } else {
                    FC_CHECK("export refuses a lying object_sha3", false);
                }
                free(side);
            } else {
                FC_CHECK("export refuses a lying object_sha3", false);
            }
        } else {
            FC_CHECK("export refuses a lying object_sha3", false);
        }
    }
    return failures;
}

static int fcw_arm_refuse_mislabeled(struct fcw_arm *a)
{
    int failures = 0;
    /* R3: an entry renamed to a key it does not hash to. */
    char misl[4096];
    if (snprintf(misl, sizeof(misl), "%s/mislabeled", a->base) <
        (int)sizeof(misl)) {
        (void)fcw_rm_rf(misl);
        if (fcw_copy_tree(a->cacheA, misl)) {
            char key2[65];
            memcpy(key2, a->key, 65);
            key2[63] = key2[63] == '0' ? '1' : '0';
            char o1[4096], s1[4096], o2[4096], s2[4096];
            if (vcs_fastobj_cache_paths(misl, a->key, o1, sizeof(o1), s1,
                                        sizeof(s1)) &&
                vcs_fastobj_cache_paths(misl, key2, o2, sizeof(o2), s2,
                                        sizeof(s2)) &&
                rename(o1, o2) == 0 && rename(s1, s2) == 0) {
                bool refused = !vcs_fastobj_carrier_export(
                    misl, a->nodeA, a->rootL, &a->stRef, a->err, sizeof(a->err));
                FC_CHECK("export refuses an entry filed under a "
                         "wrong key",
                         refused && strstr(a->err, "filed under") != NULL);
                if (!(refused && strstr(a->err, "filed under")))
                    printf("    mislabeled export: %s\n", a->err);
            } else {
                FC_CHECK(
                    "export refuses an entry filed under a wrong key",
                    false);
            }
        } else {
            FC_CHECK("export refuses an entry filed under a wrong key",
                     false);
        }
    }
    return failures;
}

static int fcw_arm_refuse_linked(struct fcw_arm *a)
{
    int failures = 0;
    failures += fcw_linked_sidecar_refusal(a->base, a->cacheA, a->key, a->nodeA,
                                            a->rootL, &a->stRef, a->err,
                                            sizeof(a->err));
    failures += fcw_linked_object_refusal(a->base, a->cacheA, a->key, a->nodeA,
                                           a->rootL, &a->stRef, a->err,
                                           sizeof(a->err));
    failures += fcw_linked_shard_refusal(a->base, a->cacheA, a->key, a->nodeA,
                                          a->rootL, &a->stRef, a->err,
                                          sizeof(a->err));
    failures += fcw_linked_admit_shard_refusal(a->base, a->key, a->nodeA, a->rootA,
                                                a->err, sizeof(a->err));
    failures += fcw_portable_partial_retry(a->base, a->nodeA, a->rootA);
#if defined(__linux__)
    failures += fcw_anonymous_crash_refusal(a->base, a->nodeA, a->rootA);
#endif
    return failures;
}

/* Hand-built carrier: stores the lying object and sidecar under key2 into
 * store R and returns whether every put landed. The manifest and wire are
 * freed here, once the store holds them. */
static bool fcw_arm_handbuilt_store(struct fcw_arm *a, const char *key2,
                                    uint8_t *obj, size_t obj_len,
                                    uint8_t *side, size_t side_len)
{
    char cobj[4096], cside[4096];
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool built =
        snprintf(cobj, sizeof(cobj), "%s/%s.o",
                 VCS_FASTOBJ_CARRIER_DIR, key2) <
            (int)sizeof(cobj) &&
        snprintf(cside, sizeof(cside), "%s/%s.json",
                 VCS_FASTOBJ_CARRIER_DIR, key2) <
            (int)sizeof(cside) &&
        vcs_package_content_add_file(&manifest, cobj,
                                     VCS_PACKAGE_MODE_FILE, obj,
                                     obj_len) &&
        vcs_package_content_add_file(&manifest, cside,
                                     VCS_PACKAGE_MODE_FILE, side,
                                     side_len) &&
        vcs_package_manifest_serialize(&manifest, &wire,
                                       &wire_len) &&
        vcs_package_manifest_root(&manifest, a->rootL);
    a->storeR = vcs_package_store_open(
        a->dirR, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    uint8_t stored[32] = {0};
    bool stored_ok =
        built && a->storeR != NULL &&
        vcs_package_store_put_manifest(a->storeR, wire, wire_len,
                                       stored) ==
            VCS_PACKAGE_STORE_OK &&
        memcmp(stored, a->rootL, 32) == 0 &&
        vcs_package_content_put_file(a->storeR, a->rootL, cobj, obj,
                                     obj_len) ==
            VCS_PACKAGE_STORE_OK &&
        vcs_package_content_put_file(a->storeR, a->rootL, cside, side,
                                     side_len) ==
            VCS_PACKAGE_STORE_OK;
    free(wire);
    vcs_package_manifest_free(&manifest);
    return stored_ok;
}

/* ADMIT and the public-shape gate must both refuse the stored lying carrier. */
static int fcw_arm_handbuilt_admit(struct fcw_arm *a)
{
    int failures = 0;
    char admit_dir[4096];
    if (snprintf(admit_dir, sizeof(admit_dir), "%s/admitX", a->base) <
        (int)sizeof(admit_dir)) {
        bool refused =
            !vcs_fastobj_carrier_admit(admit_dir, a->storeR,
                                       a->rootL, &a->stRef, a->err,
                                       sizeof(a->err));
        FC_CHECK("admit refuses a carrier whose sidecar "
                 "lies about its key",
                 refused &&
                     strstr(a->err, "filed under") != NULL);
        if (!(refused && strstr(a->err, "filed under")))
            printf("    lying admit: %s\n", a->err);
    }
    /* The public-shape gate runs the same proof the admit
     * above just refused: no shape, no announce, no serve. */
    struct vcs_package_public_verdict lie_v;
    enum vcs_package_public_shape pub_l =
        vcs_package_public_shape_classify(a->storeR, a->rootL,
                                          &lie_v);
    FC_CHECK("the public-shape gate refuses the lying "
             "carrier",
             pub_l == VCS_PACKAGE_PUBLIC_REFUSED &&
                 lie_v.rule != NULL &&
                 strncmp(lie_v.rule, "fastobj-carrier",
                         15) == 0);
    return failures;
}

static int fcw_arm_refuse_handbuilt(struct fcw_arm *a)
{
    int failures = 0;
    /* R4: a hand-built carrier whose sidecar is filed under a key it
     * does not hash to — ADMIT must refuse at the destination. */
    char o[4096], s[4096];
    size_t obj_len = 0, side_len = 0;
    uint8_t *obj = NULL, *side = NULL;
    if (vcs_fastobj_cache_paths(a->cacheA, a->key, o, sizeof(o), s,
                                sizeof(s)) &&
        (obj = fcw_read_file(
             o, VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES, &obj_len)) !=
            NULL &&
        (side = fcw_read_file(
             s, VCS_FASTOBJ_SIDECAR_MAX_BYTES, &side_len)) !=
            NULL) {
        char key2[65];
        memcpy(key2, a->key, 65);
        key2[63] = key2[63] == '0' ? '1' : '0';
        bool stored_ok = fcw_arm_handbuilt_store(a, key2, obj, obj_len,
                                                 side, side_len);
        FC_CHECK("lying carrier hand-built and stored", stored_ok);
        if (stored_ok)
            failures += fcw_arm_handbuilt_admit(a);
    } else {
        FC_CHECK("lying carrier hand-built and stored", false);
    }
    free(obj);
    free(side);
    return failures;
}

static int fcw_arm_refusals(struct fcw_arm *a)
{
    int failures = 0;
    /* ── refusal legs: nothing above is trusted, everything re-proves ── */
    FC_CHECK("a real cache entry was found for the refusal legs",
             fcw_first_entry(a->cacheA, a->key));
    if (strlen(a->key) == 64u) {
        failures += fcw_arm_refuse_torn(a);
        failures += fcw_arm_refuse_lying(a);
        failures += fcw_arm_refuse_mislabeled(a);
        failures += fcw_arm_refuse_linked(a);
        failures += fcw_arm_refuse_handbuilt(a);
    }
    return failures;
}

static int fcw_arm_second(struct fcw_arm *a)
{
    int failures = fcw_arm_shape_a(a);
    failures += fcw_arm_reexport_c(a);
    failures += fcw_arm_fetch_admit(a);
    failures += fcw_arm_reexport_d(a);
    failures += fcw_arm_build_warm(a);
    failures += fcw_arm_receipts_emit(a);
    failures += fcw_arm_receipts_ids(a);
    failures += fcw_arm_bypass_legs(a);
    return failures;
}

static int fcw_arm_third(struct fcw_arm *a)
{
    int failures = fcw_arm_testless_prepare(a);
    if (a->testless_ready) {
        failures += fcw_arm_testless_refuse_allow(a);
        failures += fcw_arm_testless_receipt(a);
    }
    failures += fcw_arm_finding_prepare(a);
    if (a->finding_ready) {
        failures += fcw_arm_finding_run(a);
        failures += fcw_arm_finding_receipt(a);
    }
    return failures + fcw_arm_refusals(a);
}

static int test_fastobj_carrier_platform_arm(void)
{
    struct fcw_arm a;
    int failures = 0;
    printf("fastobj_carrier: object-set carrier, offline proof\n");

    /* Everything done: cleanup touches is declared and initialized before
     * the first goto done. */
    memset(&a, 0, sizeof(a));
    vcs_package_prepared_init(&a.prep);
    vcs_package_prepared_init(&a.prepT);
    vcs_package_prepared_init(&a.prepF);

    failures += fcw_arm_setup(&a);
    if (a.fatal)
        return 1;
    failures += fcw_arm_first(&a);
    if (a.stop)
        goto done;
    failures += fcw_arm_second(&a);
    failures += fcw_arm_third(&a);

done:
    free(a.r1);
    free(a.r2);
    free(a.rT);
    free(a.rF);
    vcs_package_prepared_free(&a.prep);
    vcs_package_prepared_free(&a.prepT);
    vcs_package_prepared_free(&a.prepF);
    if (a.nodeA)
        vcs_package_store_close(a.nodeA);
    if (a.nodeB)
        vcs_package_store_close(a.nodeB);
    if (a.nodeC)
        vcs_package_store_close(a.nodeC);
    if (a.nodeD)
        vcs_package_store_close(a.nodeD);
    if (a.storeR)
        vcs_package_store_close(a.storeR);
    if (failures == 0) {
        (void)fcw_rm_rf(a.base);
    } else {
        printf("fastobj_carrier: scratch kept for inspection: %s\n", a.base);
    }
    printf("fastobj_carrier: %s (%d failure%s)\n",
           failures ? "FAIL" : "PASS", failures, failures == 1 ? "" : "s");
    return failures;
}

#else /* _WIN32 */

/* Every candidate build here runs the confined package verifier with
 * --require-full-isolation; Windows has no qualified package sandbox, so no
 * case in this group can run there. */
static int test_fastobj_carrier_platform_arm(void)
{
    printf("test_fastobj_carrier: SKIP (Windows): confined package builds "
           "require a qualified full-isolation backend\n");
    return 0;
}

#endif /* !_WIN32 */

#if !defined(_WIN32)
/* Controls for fcw_rm_rf. Each case builds <base>/target/keep and the symbolic
 * link <base>/link -> target (a relative sibling name, so the link can only
 * resolve to the directory the case just created), runs the remover on the
 * link, and requires the link gone with the directory and the sentinel
 * content intact. The trailing-separator case passes "<base>/link/". The
 * case cleanup unlinks the link first, then removes the sentinel and the
 * two directories with non-recursive calls. */
static const char fcw_nofollow_text[] = "keep-me";

static bool fcw_nofollow_fixture(const char *target, const char *keep,
                                 const char *link)
{
    if (mkdir(target, 0700) != 0)
        return false;
    FILE *f = fopen(keep, "wb");
    if (!f)
        return false;
    size_t want = sizeof(fcw_nofollow_text) - 1;
    bool wrote = fwrite(fcw_nofollow_text, 1, want, f) == want;
    if (fclose(f) != 0 || !wrote)
        return false;
    return symlink("target", link) == 0;
}

static bool fcw_nofollow_text_intact(const char *keep)
{
    char buf[32];
    FILE *f = fopen(keep, "rb");
    if (!f)
        return false;
    size_t got = fread(buf, 1, sizeof(buf), f);
    bool read_ok = ferror(f) == 0;
    bool closed = fclose(f) == 0;
    size_t want = sizeof(fcw_nofollow_text) - 1;
    return read_ok && closed && got == want &&
           memcmp(buf, fcw_nofollow_text, want) == 0;
}

static bool fcw_nofollow_cleanup(const char *base, const char *target,
                                 const char *keep, const char *link)
{
    struct stat st;
    bool ok = true;
    if (lstat(link, &st) == 0 && unlink(link) != 0)
        ok = false;
    if (unlink(keep) != 0)
        ok = false;
    if (rmdir(target) != 0)
        ok = false;
    if (rmdir(base) != 0)
        ok = false;
    return ok;
}

static bool fcw_nofollow_run(bool trailing_sep)
{
    char base[512], target[640], keep[704], link[640], arg[648];
    test_make_tmpdir(base, sizeof(base), "fastobj_carrier",
                     trailing_sep ? "nofollow_slash" : "nofollow_link");
    snprintf(target, sizeof(target), "%s/target", base);
    snprintf(keep, sizeof(keep), "%s/keep", target);
    snprintf(link, sizeof(link), "%s/link", base);
    snprintf(arg, sizeof(arg), trailing_sep ? "%s/" : "%s", link);

    bool linked = fcw_nofollow_fixture(target, keep, link);
    bool removed = false;
    if (linked)
        removed = fcw_rm_rf(arg);

    struct stat st;
    bool link_gone = lstat(link, &st) != 0 && errno == ENOENT;
    bool kept = fcw_nofollow_text_intact(keep);
    bool target_kept = stat(target, &st) == 0 && S_ISDIR(st.st_mode);
    bool clean = fcw_nofollow_cleanup(base, target, keep, link);

    bool ok = linked & removed & link_gone & kept & target_kept & clean;
    if (!ok)
        printf("  fastobj_carrier: nofollow (%s) linked=%d removed=%d link_gone=%d "
               "kept=%d target_kept=%d clean=%d\n",
               trailing_sep ? "trailing separator" : "plain link", linked,
               removed, link_gone, kept, target_kept, clean);
    return ok;
}

static int fcw_nofollow_plain_link(void)
{
    int failures = 0;
    FC_CHECK("remover unlinks a symbolic link and keeps its target",
          fcw_nofollow_run(false));
    return failures;
}

static int fcw_nofollow_trailing_sep(void)
{
    int failures = 0;
    FC_CHECK("remover keeps the target of a symbolic link named with a trailing separator",
          fcw_nofollow_run(true));
    return failures;
}
#endif /* !_WIN32 */

int test_fastobj_carrier(void)
{
    int failures = 0;
#if !defined(_WIN32)
    failures += fcw_empty_export_regression();
    failures += fcw_nofollow_plain_link();
    failures += fcw_nofollow_trailing_sep();
#endif
    return failures + test_fastobj_carrier_platform_arm();
}
