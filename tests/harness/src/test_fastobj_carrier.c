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
    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT;
    if (!S_ISDIR(st.st_mode))
        return unlink(path) == 0;
    DIR *d = opendir(path);
    if (!d)
        return false;
    struct dirent *e;
    bool ok = true;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char child[4096];
        if (snprintf(child, sizeof(child), "%s/%s", path, e->d_name) >=
            (int)sizeof(child)) {
            ok = false;
            continue;
        }
        ok = fcw_rm_rf(child) && ok;
    }
    closedir(d);
    return rmdir(path) == 0 && ok;
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
        "zclassic23-package-verify-dev",
        "zclassic23-package-verify",
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
    char source_arg[4200], recipe_arg[4200], emit_arg[4096],
         lock_arg[128], fast_arg[4096], name_arg[128], cpu_arg[64],
         plan_arg[4200];
    if (snprintf(source_arg, sizeof(source_arg),
                 "--zbuild-package-source=%s", pkg_abs) >=
            (int)sizeof(source_arg) ||
        snprintf(recipe_arg, sizeof(recipe_arg),
                 "--zbuild-package-recipe=%s", recipe_abs) >=
            (int)sizeof(recipe_arg) ||
        snprintf(emit_arg, sizeof(emit_arg), "--emit=%s", emit_dir) >=
            (int)sizeof(emit_arg) ||
        snprintf(lock_arg, sizeof(lock_arg), "--lock-root=%s", lock_hex) >=
            (int)sizeof(lock_arg) ||
        snprintf(fast_arg, sizeof(fast_arg), "--fast-cache=%s",
                 cache_dir) >= (int)sizeof(fast_arg) ||
        snprintf(name_arg, sizeof(name_arg),
                 "--zbuild-package-name=fixture/tiny-lines") >=
            (int)sizeof(name_arg) ||
        snprintf(plan_arg, sizeof(plan_arg), "--plan=%s.plan", emit_dir) >=
            (int)sizeof(plan_arg) ||
        snprintf(cpu_arg, sizeof(cpu_arg),
                 "--zbuild-package-max-cpu-seconds=120") >=
            (int)sizeof(cpu_arg))
        return;
    const char *argv[] = {worker,       root_hex,     source_arg,
                          recipe_arg,   name_arg,
                          "--zbuild-package-profile=standard",
                          cpu_arg,      emit_arg,     lock_arg,
                          fast_arg, "--require-full-isolation",
                          NULL, NULL, NULL};
    fcw_candidate_options(argv + 11, allow_testless, with_plan, plan_arg);
    int fds[2];
    if (pipe(fds) != 0)
        return;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return;
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
    close(fds[1]);
    /* Drain until EOF, a 1 MiB cap, or 300 s of silence — whichever
     * comes first. */
    size_t cap = 1024u * 1024u, len = 0;
    char *text = malloc(cap);
    if (text) {
        int idle = 0;
        while (len + 1u < cap && idle < 300) {
            struct pollfd pfd = {fds[0], POLLIN, 0};
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
            ssize_t got = read(fds[0], text + len, cap - len - 1u);
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
    }
    /* Reap: up to 60 s past EOF for the exit syscall, then SIGKILL. */
    int status = 0;
    bool reaped = false, killed = false;
    for (int i = 0; i < 60 && !reaped; i++) {
        if (waitpid(pid, &status, WNOHANG) == pid) {
            reaped = true;
            break;
        }
        sleep(1); /* real-clock: pre-existing bounded poll loop, seeded when check_no_real_clock_test_deadline.sh was introduced */
    }
    if (!reaped) {
        kill(pid, SIGKILL);
        killed = true;
        (void)waitpid(pid, &status, 0);
    }
    close(fds[0]);
    out->exit_code = !killed && WIFEXITED(status) ? WEXITSTATUS(status)
                                                  : -1;
    out->ok = !killed && out->exit_code == 0;
    if (text) {
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

static int test_fastobj_carrier_platform_arm(void)
{
    int failures = 0;
    printf("fastobj_carrier: object-set carrier, offline proof\n");

    /* Everything done: cleanup touches is declared and initialized before
     * the first goto done. */
    char err[512] = "";
    struct vcs_package_prepared prep;
    vcs_package_prepared_init(&prep);
    struct vcs_package_prepared prepT;
    vcs_package_prepared_init(&prepT);
    struct vcs_package_prepared prepF;
    vcs_package_prepared_init(&prepF);
    struct vcs_fastobj_carrier_stats stA, stC, stF, stAd, stD, stRef;
    memset(&stA, 0, sizeof(stA));
    memset(&stC, 0, sizeof(stC));
    memset(&stF, 0, sizeof(stF));
    memset(&stAd, 0, sizeof(stAd));
    memset(&stD, 0, sizeof(stD));
    memset(&stRef, 0, sizeof(stRef));
    uint8_t rootA[32] = {0}, rootC[32] = {0}, rootD[32] = {0}, rootL[32] = {0};
    struct vcs_package_store *nodeA = NULL, *nodeB = NULL, *nodeC = NULL,
                             *nodeD = NULL, *storeR = NULL;
    size_t r1_len = 0, r2_len = 0, rT_len = 0, rF_len = 0;
    uint8_t *r1 = NULL, *r2 = NULL, *rT = NULL, *rF = NULL;

    /* The confined worker ships beside this binary — never from PATH. */
    char worker[4096];
    bool have_worker = fcw_worker_path(worker, sizeof(worker));
    FC_CHECK("package verifier beside the test binary (make dev-bin)",
             have_worker);
    char cwd[3072];
    char base[4096];
    bool base_ok = getcwd(cwd, sizeof(cwd)) != NULL &&
        snprintf(base, sizeof(base), "%s/test-tmp/fastobj_carrier_%ld",
                 cwd, (long)getpid()) < (int)sizeof(base);
    if (!base_ok || !have_worker) {
        printf("fastobj_carrier: FAIL (setup)\n");
        return 1;
    }
    (void)fcw_rm_rf(base);
    if (!fcw_mkdir_p(base)) {
        printf("fastobj_carrier: FAIL (scratch %s)\n", base);
        return 1;
    }

    char pkg[4096], cacheA[4096], cacheB[4096], emit1[4096], emit2[4096],
         recipe_path[4096], dirA[4096], dirB[4096], dirC[4096], dirD[4096],
         dirR[4096];
    bool paths_ok =
        snprintf(pkg, sizeof(pkg), "%s/pkg", base) < (int)sizeof(pkg) &&
        snprintf(cacheA, sizeof(cacheA), "%s/cacheA", base) <
            (int)sizeof(cacheA) &&
        snprintf(cacheB, sizeof(cacheB), "%s/cacheB", base) <
            (int)sizeof(cacheB) &&
        snprintf(emit1, sizeof(emit1), "%s/emit1", base) <
            (int)sizeof(emit1) &&
        snprintf(emit2, sizeof(emit2), "%s/emit2", base) <
            (int)sizeof(emit2) &&
        snprintf(recipe_path, sizeof(recipe_path), "%s/recipe.wire", base) <
            (int)sizeof(recipe_path) &&
        snprintf(dirA, sizeof(dirA), "%s/nodeA", base) < (int)sizeof(dirA) &&
        snprintf(dirB, sizeof(dirB), "%s/nodeB", base) < (int)sizeof(dirB) &&
        snprintf(dirC, sizeof(dirC), "%s/nodeC", base) < (int)sizeof(dirC) &&
        snprintf(dirD, sizeof(dirD), "%s/nodeD", base) < (int)sizeof(dirD) &&
        snprintf(dirR, sizeof(dirR), "%s/storeR", base) < (int)sizeof(dirR);
    FC_CHECK("scratch paths laid out", paths_ok);
    if (!paths_ok)
        goto done;

    /* 1. prepare the tiny-lines fixture (contexts/commons/modules/vcs only — the candidate
     * proof action needs no signed release). */
    FC_CHECK("tiny-lines fixture copied to scratch",
             fcw_copy_tree("tests/harness/fixtures/zcode/tiny-lines", pkg));
    struct vcs_package_prepare_options opts;
    memset(&opts, 0, sizeof(opts));
    opts.dir = pkg;
    /* The release layer validates the publisher pubkey as a compressed
     * curve point, so derive a real one (the test_zcode_add idiom). */
    struct privkey sk;
    struct pubkey pk;
    memset(sk.vch, 0x11, 32);
    sk.fValid = true;
    sk.fCompressed = true;
    bool have_pk = privkey_get_pubkey(&sk, &pk);
    FC_CHECK("publisher pubkey derived for prepare", have_pk);
    if (!have_pk)
        goto done;
    memcpy(opts.publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    opts.publisher_sequence = 1;
    char prep_detail[512] = "";
    enum vcs_package_prepare_error prc =
        vcs_package_prepare(&opts, &prep, prep_detail, sizeof(prep_detail));
    FC_CHECK("package prepared (root, recipe, lock derived)",
             prc == VCS_PACKAGE_PREPARE_OK);
    if (prc != VCS_PACKAGE_PREPARE_OK)
        printf("    prepare: %s\n", prep_detail);
    char root_hex[65] = "", lock_hex[65] = "";
    zcl_hex_encode(prep.package_root, 32, root_hex);
    zcl_hex_encode(prep.lock_root, 32, lock_hex);
    FC_CHECK("recipe wire written for the worker",
             prc == VCS_PACKAGE_PREPARE_OK &&
                 fcw_write_file(recipe_path, prep.recipe_wire,
                                prep.recipe_wire_len));
    if (prc != VCS_PACKAGE_PREPARE_OK)
        goto done;

    /* 2. candidate build #1 on a COLD cacheA: the compile really runs. */
    struct fcw_build_result run1, run2;
    memset(&run1, 0, sizeof(run1));
    memset(&run2, 0, sizeof(run2));
    fcw_candidate_build(worker, root_hex, pkg, recipe_path, emit1, lock_hex,
                        cacheA, false, false, &run1);
    FC_CHECK("candidate build #1 (cold cacheA) succeeded", run1.ok);
    if (!run1.ok) {
        printf("    build #1 exit %d: %.200s\n", run1.exit_code,
               run1.first_line);
        printf("    build #1 final: %.240s\n", run1.last_line);
    }
    FC_CHECK("build #1 compiled both library and test objects",
             run1.ok && run1.misses == 2u && run1.hits == 0u);
    printf("    build #1: hits=%llu misses=%llu\n", run1.hits, run1.misses);
    if (!run1.ok)
        goto done;

    /* 3. export cacheA into store nodeA as ONE content.v2 carrier. */
    nodeA = vcs_package_store_open(dirA, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    bool expA = nodeA != NULL && vcs_fastobj_carrier_export(
                                    cacheA, nodeA, rootA, &stA, err,
                                    sizeof(err));
    FC_CHECK("cacheA exported as one content.v2 carrier", expA);
    if (!expA)
        printf("    export: %s\n", err);
    FC_CHECK("carrier entries == build #1 misses",
             expA && stA.entries == (uint32_t)run1.misses);
    FC_CHECK("carrier files are object+sidecar pairs",
             expA && stA.files == 2u * stA.entries);
    FC_CHECK("carrier carries real object bytes",
             expA && stA.object_bytes > 0u);
    if (!expA)
        goto done;

    /* 4. the carrier has a public shape: a -packagehost=1 node may announce
     *    and serve it; the serve-time proof is the consumer's admit proof. */
    struct vcs_package_public_verdict shape_v;
    enum vcs_package_public_shape pub =
        vcs_package_public_shape_classify(nodeA, rootA, &shape_v);
    FC_CHECK("exported carrier classifies as fastobj-carrier",
             pub == VCS_PACKAGE_PUBLIC_FASTOBJ_CARRIER);
    FC_CHECK("the carrier rule is its shape string",
             shape_v.rule != NULL &&
                 strcmp(shape_v.rule,
                        vcs_package_public_shape_string(pub)) == 0);
    FC_CHECK("fastobj carrier is not licensed content",
             !vcs_package_public_shape_licensed(pub));
    FC_CHECK("read-only carrier verify passes on the exporter's store",
             vcs_fastobj_carrier_verify(nodeA, rootA, err, sizeof(err)));

    /* 5. re-export into a THIRD store: the root must not move. */
    nodeC = vcs_package_store_open(dirC, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    bool expC = nodeC != NULL && vcs_fastobj_carrier_export(
                                     cacheA, nodeC, rootC, &stC, err,
                                     sizeof(err));
    FC_CHECK("re-export into a third store succeeded", expC);
    if (!expC)
        printf("    re-export: %s\n", err);
    FC_CHECK("the carrier root is deterministic (same cache, same root)",
             expC && memcmp(rootA, rootC, 32) == 0);

    /* 6. fetch store-to-store: the offline stand-in for the swarm wire. */
    nodeB = vcs_package_store_open(dirB, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    bool fetched = nodeB != NULL && vcs_fastobj_carrier_fetch(
                                        nodeB, nodeA, rootA, &stF, err,
                                        sizeof(err));
    FC_CHECK("carrier fetched store-to-store into nodeB", fetched);
    if (!fetched)
        printf("    fetch: %s\n", err);
    FC_CHECK("fetched carrier carries the same entries",
             fetched && stF.entries == stA.entries);

    failures += fcw_fetch_resume(nodeB, nodeA, rootA, dirB, dirA, fetched);

    /* 7. admit nodeB's carrier into a FRESH cacheB. */
    bool admitted = fetched && vcs_fastobj_carrier_admit(
                                   cacheB, nodeB, rootA, &stAd, err,
                                   sizeof(err));
    FC_CHECK("carrier admitted into a fresh cacheB", admitted);
    if (!admitted)
        printf("    admit: %s\n", err);
    FC_CHECK("cacheB holds every carried entry",
             admitted && stAd.entries == stA.entries);

    /* 8. re-export cacheB into a FOURTH store: same root again. */
    nodeD = vcs_package_store_open(dirD, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    bool expD = nodeD != NULL && vcs_fastobj_carrier_export(
                                     cacheB, nodeD, rootD, &stD, err,
                                     sizeof(err));
    FC_CHECK("cacheB re-exported into a fourth store", expD);
    if (!expD)
        printf("    re-export cacheB: %s\n", err);
    FC_CHECK("round-trip root identical (cacheB bytes == cacheA bytes)",
             expD && memcmp(rootA, rootD, 32) == 0);

    /* 9. Adding dependency-plan evidence must reuse the same object digest. */
    fcw_candidate_build(worker, root_hex, pkg, recipe_path, emit2, lock_hex,
                        cacheB, false, true, &run2);
    FC_CHECK("candidate build #2 (warm cacheB) succeeded", run2.ok);
    if (!run2.ok)
        printf("    build #2 exit %d: %.200s\n", run2.exit_code,
               run2.first_line);
    printf("    build #2: hits=%llu misses=%llu\n", run2.hits, run2.misses);
    FC_CHECK("build #2 has no eligible object misses",
             run2.ok && run2.misses == 0u);
    FC_CHECK("build #2 hit every entry build #1 missed",
             run2.ok && run2.hits == run1.misses);
    failures += fcw_check_perf(&run1, &run2);

    /* 10. the ZCLBLD receipts are byte-identical. */
    char report1[4096], report2[4096];
    bool got_reports =
        snprintf(report1, sizeof(report1), "%s/build-report", emit1) <
            (int)sizeof(report1) &&
        snprintf(report2, sizeof(report2), "%s/build-report", emit2) <
            (int)sizeof(report2);
    if (got_reports) {
        r1 = fcw_read_file(report1, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES,
                           &r1_len);
        r2 = fcw_read_file(report2, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES,
                           &r2_len);
    }
    FC_CHECK("both ZCLBLD build-reports emitted", r1 != NULL && r2 != NULL);
    FC_CHECK("build-report #2 is byte-identical to #1",
             r1 && r2 && r1_len == r2_len && memcmp(r1, r2, r1_len) == 0);
    struct vcs_package_build_receipt rec1, rec2;
    uint8_t id1[32] = {0}, id2[32] = {0};
    bool ids_ok = r1 && r2 &&
        vcs_package_build_parse(r1, r1_len, &rec1) == VCS_PACKAGE_BUILD_OK &&
        vcs_package_build_parse(r2, r2_len, &rec2) == VCS_PACKAGE_BUILD_OK &&
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

#if defined(__linux__)
    failures += fcw_asm_bypass(base, worker, &pk, false);
    failures += fcw_attribute_bypass(base, worker, &pk);
    failures += fcw_test_cache_failure(base, worker, &pk);
    failures += fcw_program_cache_probe(base, worker, &pk);
#elif defined(__APPLE__)
    failures += fcw_asm_bypass(base, worker, &pk, false);
    failures += fcw_apple_attribute_spellings(base, worker, &pk);
#endif

    /* 11. testless standard-profile refusal: a copy without tests/ is
     * REFUSED with exit 6 in the evidence shape, and BUILDS with
     * --allow-testless-standard, recording test_ran=false,
     * result_class=BUILD_PASS. */
    char pkgT[4096], recipeT_path[4096], emitT1[4096], emitT2[4096],
         cacheT[4096], testsT[4096];
    bool pathsT_ok =
        snprintf(pkgT, sizeof(pkgT), "%s/pkgT", base) < (int)sizeof(pkgT) &&
        snprintf(recipeT_path, sizeof(recipeT_path), "%s/recipeT.wire",
                 base) < (int)sizeof(recipeT_path) &&
        snprintf(emitT1, sizeof(emitT1), "%s/emitT1", base) <
            (int)sizeof(emitT1) &&
        snprintf(emitT2, sizeof(emitT2), "%s/emitT2", base) <
            (int)sizeof(emitT2) &&
        snprintf(cacheT, sizeof(cacheT), "%s/cacheT", base) <
            (int)sizeof(cacheT) &&
        snprintf(testsT, sizeof(testsT), "%s/tests", pkgT) <
            (int)sizeof(testsT);
    bool testless_ready = pathsT_ok &&
        fcw_copy_tree("tests/harness/fixtures/zcode/tiny-lines", pkgT) &&
        fcw_rm_rf(testsT);
    struct vcs_package_prepare_options optsT;
    memset(&optsT, 0, sizeof(optsT));
    optsT.dir = pkgT;
    memcpy(optsT.publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    optsT.publisher_sequence = 1;
    char prepT_detail[512] = "";
    enum vcs_package_prepare_error prcT = VCS_PACKAGE_PREPARE_ERR_IO;
    if (testless_ready)
        prcT = vcs_package_prepare(&optsT, &prepT, prepT_detail,
                                   sizeof(prepT_detail));
    char rootT_hex[65] = "", lockT_hex[65] = "";
    if (prcT == VCS_PACKAGE_PREPARE_OK) {
        zcl_hex_encode(prepT.package_root, 32, rootT_hex);
        zcl_hex_encode(prepT.lock_root, 32, lockT_hex);
    }
    testless_ready =
        testless_ready && prcT == VCS_PACKAGE_PREPARE_OK &&
        fcw_write_file(recipeT_path, prepT.recipe_wire,
                       prepT.recipe_wire_len);
    FC_CHECK("testless fixture variant (tests/ dropped) prepared",
             testless_ready);
    if (!testless_ready && prcT != VCS_PACKAGE_PREPARE_OK)
        printf("    prepare testless: %s\n", prepT_detail);
    if (testless_ready) {
        struct fcw_build_result tref, tok;
        memset(&tref, 0, sizeof(tref));
        memset(&tok, 0, sizeof(tok));
        fcw_candidate_build(worker, rootT_hex, pkgT, recipeT_path, emitT1,
                            lockT_hex, cacheT, false, false, &tref);
        FC_CHECK("evidence-shape standard run of a testless package "
                 "refuses (exit 6 + refusal line)",
                 tref.exit_code == 6 && tref.saw_refusal);
        if (!(tref.exit_code == 6 && tref.saw_refusal))
            printf("    testless refuse: exit %d: %.200s\n",
                   tref.exit_code, tref.first_line);
        fcw_candidate_build(worker, rootT_hex, pkgT, recipeT_path, emitT2,
                            lockT_hex, cacheT, true, false, &tok);
        FC_CHECK("reproduce-shape standard run of a testless package "
                 "builds", tok.ok);
        FC_CHECK("testless build reports no test processes",
                 fcw_testless_perf(&tok));
        if (!tok.ok)
            printf("    testless allow: exit %d: %.200s\n", tok.exit_code,
                   tok.first_line);
        char reportT[4096];
        if (tok.ok &&
            snprintf(reportT, sizeof(reportT), "%s/build-report", emitT2) <
                (int)sizeof(reportT))
            rT = fcw_read_file(reportT, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES,
                               &rT_len);
        struct vcs_package_build_receipt recT;
        bool recT_ok =
            rT != NULL && vcs_package_build_parse(rT, rT_len, &recT) ==
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
    }

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
    char pkgF[4096], recipeF_path[4096], emitF[4096], cacheF[4096],
         testF_path[4096], helperF_path[4096];
    bool pathsF_ok =
        snprintf(pkgF, sizeof(pkgF), "%s/pkgF", base) < (int)sizeof(pkgF) &&
        snprintf(recipeF_path, sizeof(recipeF_path), "%s/recipeF.wire",
                 base) < (int)sizeof(recipeF_path) &&
        snprintf(emitF, sizeof(emitF), "%s/emitF", base) <
            (int)sizeof(emitF) &&
        snprintf(cacheF, sizeof(cacheF), "%s/cacheF", base) <
            (int)sizeof(cacheF) &&
        snprintf(testF_path, sizeof(testF_path),
                 "%s/tests/test_tiny_lines.c", pkgF) < (int)sizeof(testF_path) &&
        snprintf(helperF_path, sizeof(helperF_path),
                 "%s/tests/uaf_helper.c", pkgF) < (int)sizeof(helperF_path);
    struct vcs_package_prepare_options optsF;
    memset(&optsF, 0, sizeof(optsF));
    optsF.dir = pkgF;
    memcpy(optsF.publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    optsF.publisher_sequence = 1;
    char prepF_detail[512] = "";
    enum vcs_package_prepare_error prcF = VCS_PACKAGE_PREPARE_ERR_IO;
    bool finding_ready = pathsF_ok &&
        fcw_copy_tree("tests/harness/fixtures/zcode/tiny-lines", pkgF) &&
        fcw_write_file(testF_path, (const uint8_t *)uaf_test,
                       sizeof(uaf_test) - 1u) &&
        fcw_write_file(helperF_path, (const uint8_t *)uaf_helper,
                       sizeof(uaf_helper) - 1u);
    if (finding_ready)
        prcF = vcs_package_prepare(&optsF, &prepF, prepF_detail,
                                   sizeof(prepF_detail));
    char rootF_hex[65] = "", lockF_hex[65] = "";
    if (prcF == VCS_PACKAGE_PREPARE_OK) {
        zcl_hex_encode(prepF.package_root, 32, rootF_hex);
        zcl_hex_encode(prepF.lock_root, 32, lockF_hex);
    }
    finding_ready =
        finding_ready && prcF == VCS_PACKAGE_PREPARE_OK &&
        fcw_write_file(recipeF_path, prepF.recipe_wire,
                       prepF.recipe_wire_len);
    FC_CHECK("use-after-free fixture variant prepared", finding_ready);
    if (!finding_ready && prcF != VCS_PACKAGE_PREPARE_OK)
        printf("    prepare findings: %s\n", prepF_detail);
    if (finding_ready) {
        struct fcw_build_result frun;
        memset(&frun, 0, sizeof(frun));
        fcw_candidate_build(worker, rootF_hex, pkgF, recipeF_path, emitF,
                            lockF_hex, cacheF, true, false, &frun);
        FC_CHECK("reproduce-shape standard run with an ASan finding still "
                 "emits (evidence, not a gate)", frun.ok);
        if (!frun.ok)
            printf("    findings run: exit %d: %.200s\n", frun.exit_code,
                   frun.first_line);
        printf("    findings run tail: %.200s\n", frun.last_line);
        char reportF[4096];
        if (frun.ok &&
            snprintf(reportF, sizeof(reportF), "%s/build-report", emitF) <
                (int)sizeof(reportF))
            rF = fcw_read_file(reportF, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES,
                               &rF_len);
        struct vcs_package_build_receipt recF;
        bool recF_ok =
            rF != NULL && vcs_package_build_parse(rF, rF_len, &recF) ==
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
    }

    /* ── refusal legs: nothing above is trusted, everything re-proves ── */

    char key[65];
    FC_CHECK("a real cache entry was found for the refusal legs",
             fcw_first_entry(cacheA, key));
    if (strlen(key) == 64u) {
        /* R1: a torn pair (sidecar deleted) refuses the WHOLE export. */
        char torn[4096];
        if (snprintf(torn, sizeof(torn), "%s/torn", base) <
            (int)sizeof(torn)) {
            (void)fcw_rm_rf(torn);
            if (fcw_copy_tree(cacheA, torn)) {
                char o[4096], s[4096];
                if (vcs_fastobj_cache_paths(torn, key, o, sizeof(o), s,
                                            sizeof(s)))
                    (void)unlink(s);
                bool refused = !vcs_fastobj_carrier_export(
                    torn, nodeA, rootL, &stRef, err, sizeof(err));
                FC_CHECK("export refuses a torn pair",
                         refused && strstr(err, "torn") != NULL);
                if (!(refused && strstr(err, "torn")))
                    printf("    torn export: %s\n", err);
            } else {
                FC_CHECK("export refuses a torn pair", false);
            }
        }

        /* R2: a sidecar whose object_sha3 lies about its object. */
        char lying[4096];
        if (snprintf(lying, sizeof(lying), "%s/lying", base) <
            (int)sizeof(lying)) {
            (void)fcw_rm_rf(lying);
            if (fcw_copy_tree(cacheA, lying)) {
                char o[4096], s[4096];
                size_t side_len = 0;
                uint8_t *side = NULL;
                if (vcs_fastobj_cache_paths(lying, key, o, sizeof(o), s,
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
                            lying, nodeA, rootL, &stRef, err, sizeof(err));
                        FC_CHECK("export refuses a lying object_sha3",
                                 refused && strstr(err, "does not hash") !=
                                               NULL);
                        if (!(refused &&
                              strstr(err, "does not hash")))
                            printf("    lying export: %s\n", err);
                    } else {
                        FC_CHECK("export refuses a lying object_sha3",
                                 false);
                    }
                    free(side);
                } else {
                    FC_CHECK("export refuses a lying object_sha3", false);
                }
            } else {
                FC_CHECK("export refuses a lying object_sha3", false);
            }
        }

        /* R3: an entry renamed to a key it does not hash to. */
        char misl[4096];
        if (snprintf(misl, sizeof(misl), "%s/mislabeled", base) <
            (int)sizeof(misl)) {
            (void)fcw_rm_rf(misl);
            if (fcw_copy_tree(cacheA, misl)) {
                char key2[65];
                memcpy(key2, key, 65);
                key2[63] = key2[63] == '0' ? '1' : '0';
                char o1[4096], s1[4096], o2[4096], s2[4096];
                if (vcs_fastobj_cache_paths(misl, key, o1, sizeof(o1), s1,
                                            sizeof(s1)) &&
                    vcs_fastobj_cache_paths(misl, key2, o2, sizeof(o2), s2,
                                            sizeof(s2)) &&
                    rename(o1, o2) == 0 && rename(s1, s2) == 0) {
                    bool refused = !vcs_fastobj_carrier_export(
                        misl, nodeA, rootL, &stRef, err, sizeof(err));
                    FC_CHECK("export refuses an entry filed under a "
                             "wrong key",
                             refused && strstr(err, "filed under") != NULL);
                    if (!(refused && strstr(err, "filed under")))
                        printf("    mislabeled export: %s\n", err);
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

        failures += fcw_linked_sidecar_refusal(base, cacheA, key, nodeA,
                                                rootL, &stRef, err,
                                                sizeof(err));
        failures += fcw_linked_object_refusal(base, cacheA, key, nodeA,
                                               rootL, &stRef, err,
                                               sizeof(err));
        failures += fcw_linked_shard_refusal(base, cacheA, key, nodeA,
                                              rootL, &stRef, err,
                                              sizeof(err));
        failures += fcw_linked_admit_shard_refusal(base, key, nodeA, rootA,
                                                    err, sizeof(err));
        failures += fcw_portable_partial_retry(base, nodeA, rootA);
#if defined(__linux__)
        failures += fcw_anonymous_crash_refusal(base, nodeA, rootA);
#endif

        /* R4: a hand-built carrier whose sidecar is filed under a key it
         * does not hash to — ADMIT must refuse at the destination. */
        {
            char o[4096], s[4096];
            size_t obj_len = 0, side_len = 0;
            uint8_t *obj = NULL, *side = NULL;
            if (vcs_fastobj_cache_paths(cacheA, key, o, sizeof(o), s,
                                        sizeof(s)) &&
                (obj = fcw_read_file(
                     o, VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES, &obj_len)) !=
                    NULL &&
                (side = fcw_read_file(
                     s, VCS_FASTOBJ_SIDECAR_MAX_BYTES, &side_len)) !=
                    NULL) {
                char key2[65];
                memcpy(key2, key, 65);
                key2[63] = key2[63] == '0' ? '1' : '0';
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
                    vcs_package_manifest_root(&manifest, rootL);
                storeR = vcs_package_store_open(
                    dirR, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
                uint8_t stored[32] = {0};
                bool stored_ok =
                    built && storeR != NULL &&
                    vcs_package_store_put_manifest(storeR, wire, wire_len,
                                                   stored) ==
                        VCS_PACKAGE_STORE_OK &&
                    memcmp(stored, rootL, 32) == 0 &&
                    vcs_package_content_put_file(storeR, rootL, cobj, obj,
                                                 obj_len) ==
                        VCS_PACKAGE_STORE_OK &&
                    vcs_package_content_put_file(storeR, rootL, cside, side,
                                                 side_len) ==
                        VCS_PACKAGE_STORE_OK;
                FC_CHECK("lying carrier hand-built and stored", stored_ok);
                if (stored_ok) {
                    char admit_dir[4096];
                    if (snprintf(admit_dir, sizeof(admit_dir), "%s/admitX",
                                 base) < (int)sizeof(admit_dir)) {
                        bool refused =
                            !vcs_fastobj_carrier_admit(admit_dir, storeR,
                                                       rootL, &stRef, err,
                                                       sizeof(err));
                        FC_CHECK("admit refuses a carrier whose sidecar "
                                 "lies about its key",
                                 refused &&
                                     strstr(err, "filed under") != NULL);
                        if (!(refused && strstr(err, "filed under")))
                            printf("    lying admit: %s\n", err);
                    }
                    /* The public-shape gate runs the same proof the admit
                     * above just refused: no shape, no announce, no serve. */
                    struct vcs_package_public_verdict lie_v;
                    enum vcs_package_public_shape pub_l =
                        vcs_package_public_shape_classify(storeR, rootL,
                                                          &lie_v);
                    FC_CHECK("the public-shape gate refuses the lying "
                             "carrier",
                             pub_l == VCS_PACKAGE_PUBLIC_REFUSED &&
                                 lie_v.rule != NULL &&
                                 strncmp(lie_v.rule, "fastobj-carrier",
                                         15) == 0);
                }
                free(wire);
                vcs_package_manifest_free(&manifest);
            } else {
                FC_CHECK("lying carrier hand-built and stored", false);
            }
            free(obj);
            free(side);
        }
    }

done:
    free(r1);
    free(r2);
    free(rT);
    free(rF);
    vcs_package_prepared_free(&prep);
    vcs_package_prepared_free(&prepT);
    vcs_package_prepared_free(&prepF);
    if (nodeA)
        vcs_package_store_close(nodeA);
    if (nodeB)
        vcs_package_store_close(nodeB);
    if (nodeC)
        vcs_package_store_close(nodeC);
    if (nodeD)
        vcs_package_store_close(nodeD);
    if (storeR)
        vcs_package_store_close(storeR);
    if (failures == 0) {
        (void)fcw_rm_rf(base);
    } else {
        printf("fastobj_carrier: scratch kept for inspection: %s\n", base);
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

int test_fastobj_carrier(void)
{
    int failures = 0;
#if !defined(_WIN32)
    failures += fcw_empty_export_regression();
#endif
    return failures + test_fastobj_carrier_platform_arm();
}
