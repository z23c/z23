/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Exercise compiler path normalization and native machine identity. */
#define _XOPEN_SOURCE 700
#include <errno.h>
#include <ftw.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct result { int status; char output[32768]; };
static volatile sig_atomic_t interrupted;
static void note_interrupt(int signal) { (void)signal; interrupted = 1; }
static char found_helper[PATH_MAX];
static int helper_visit(const char *path, const struct stat *st, int type,
                        struct FTW *ftw)
{
    (void)st; (void)ftw;
    const char *base = strrchr(path, '/');
    if (type == FTW_F && base && !strcmp(base + 1, "vendor-lock")) {
        if (snprintf(found_helper, sizeof found_helper, "%s", path) >=
            (int)sizeof found_helper) return -1;
        return 1;
    }
    return 0;
}

static bool failed(const struct result *result)
{
    return WIFEXITED(result->status) && WEXITSTATUS(result->status) != 0;
}

static bool drain(int fd, struct result *result)
{
    size_t used = 0;
    bool overflow = false, error = false;
    for (;;) {
        char discard[4096];
        void *destination = overflow ? (void *)discard : (void *)(result->output + used);
        size_t capacity = overflow ? sizeof discard : sizeof result->output - 1 - used;
        ssize_t n = read(fd, destination, capacity);
        if (n > 0) {
            if (!overflow) used += (size_t)n;
            if (used == sizeof result->output - 1) overflow = true;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) error = true;
        break;
    }
    (void)close(fd);
    result->output[used] = '\0';
    return !overflow && !error;
}

static bool write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f) return false;
    bool ok = fputs(text, f) >= 0;
    if (fclose(f) != 0) ok = false;
    if (chmod(path, 0755) != 0) ok = false;
    return ok;
}

static bool copy_file(const char *source, const char *destination)
{
    char buf[4096];
    FILE *in = fopen(source, "rb");
    if (!in) return false;
    FILE *out = fopen(destination, "wb");
    if (!out) { (void)fclose(in); return false; }
    bool ok = true;
    for (;;) {
        size_t n = fread(buf, 1, sizeof buf, in);
        if (n && fwrite(buf, 1, n, out) != n) { ok = false; break; }
        if (n < sizeof buf) {
            if (ferror(in)) ok = false;
            break;
        }
    }
    if (fclose(in) != 0) ok = false;
    if (fclose(out) != 0) ok = false;
    if (chmod(destination, 0755) != 0) ok = false;
    return ok;
}

static void run_build_child(const char *root, const char *cc, const char *path,
                            const char *home, const char *ar, const char *archive,
                            bool provenance, int read_fd, int write_fd)
{
    (void)close(read_fd);
    if (chdir(root) != 0 || dup2(write_fd, STDOUT_FILENO) < 0 ||
        dup2(write_fd, STDERR_FILENO) < 0) _exit(126);
    (void)close(write_fd);
    if (setenv("HOME", home, 1) || setenv("PATH", path, 1) ||
        setenv("VENDOR_CC", cc, 1) || setenv("VENDOR_AR", ar, 1) ||
        setenv("ZCL_VENDOR_OFFLINE", "1", 1)) _exit(125);
    if (provenance)
        execl("tools/scripts/build_vendor.sh", "tools/scripts/build_vendor.sh",
              "--check-provenance", archive, (char *)NULL);
    else
        execl("tools/scripts/build_vendor.sh", "tools/scripts/build_vendor.sh",
              archive, (char *)NULL);
    _exit(127);
}

static bool run_build(const char *root, const char *cc, const char *path,
                      const char *home, const char *ar, const char *archive,
                      bool provenance, struct result *result)
{
    int fds[2];
    if (pipe(fds) != 0) return false;
    pid_t child = fork();
    if (child == 0)
        run_build_child(root, cc, path, home, ar, archive, provenance, fds[0], fds[1]);
    (void)close(fds[1]);
    if (child < 0) { (void)close(fds[0]); return false; }
    bool drained = drain(fds[0], result);
    pid_t got;
    do { got = waitpid(child, &result->status, 0); } while (got < 0 && errno == EINTR);
    return drained && got == child;
}

static bool path_log(const char *root, char *invoked, size_t invoked_size,
                     char *path, size_t path_size)
{
    char filename[PATH_MAX];
    if (snprintf(filename, sizeof filename, "%s/path-cc.log", root) >=
        (int)sizeof filename) return false;
    FILE *f = fopen(filename, "r");
    if (!f) return false;
    bool ok = fgets(invoked, (int)invoked_size, f) && fgets(path, (int)path_size, f);
    if (fclose(f) != 0) ok = false;
    if (!ok) return false;
    invoked[strcspn(invoked, "\n")] = '\0';
    path[strcspn(path, "\n")] = '\0';
    return true;
}

static bool path_starts(const char *path, const char *directory)
{
    size_t n = strlen(directory);
    return !strncmp(path, directory, n) && (path[n] == ':' || path[n] == '\0');
}

static bool path_under(const char *path, const char *directory)
{
    size_t n = strlen(directory);
    return !strncmp(path, directory, n) && (path[n] == '/' || path[n] == '\0');
}

static bool probe(const char *root, const char *cc, const char *path, const char *home,
                  const char *ar, const char *expected_cc, const char *expected_dir,
                  bool preserve_absolute)
{
    char logfile[PATH_MAX];
    if (snprintf(logfile, sizeof logfile, "%s/path-cc.log", root) >=
        (int)sizeof logfile) return false;
    (void)unlink(logfile);
    struct result result = {0};
    if (!run_build(root, cc, path, home, ar, "libz.a", true, &result) || !failed(&result))
        return false;
    char invoked[256], received[4096];
    if (!path_log(root, invoked, sizeof invoked, received, sizeof received)) {
        fprintf(stderr, "compiler fixture was not invoked: %s\n", result.output);
        return false;
    }
    if (!strcmp(invoked, expected_cc) &&
        (preserve_absolute ? !path_starts(received, expected_dir) :
         path_starts(received, expected_dir))) return true;
    fprintf(stderr, "compiler mismatch: invoked=[%s] expected=[%s] PATH=[%s] expected_dir=[%s]\n",
            invoked, expected_cc, received, expected_dir);
    return false;
}

struct native_machine_fixture {
    char tools[PATH_MAX], bins[PATH_MAX], cc[PATH_MAX], clang[PATH_MAX], ar[PATH_MAX];
    char native[PATH_MAX];
};

static bool native_machine_setup(const char *root, struct native_machine_fixture *fixture)
{
    if (snprintf(fixture->tools, sizeof fixture->tools, "%s/tools", root) >=
            (int)sizeof fixture->tools ||
        snprintf(fixture->bins, sizeof fixture->bins, "%s/bin", root) >=
            (int)sizeof fixture->bins ||
        snprintf(fixture->cc, sizeof fixture->cc, "%s/tools/cc", root) >=
            (int)sizeof fixture->cc ||
        snprintf(fixture->clang, sizeof fixture->clang, "%s/tools/native-clang", root) >=
            (int)sizeof fixture->clang ||
        snprintf(fixture->ar, sizeof fixture->ar, "%s/bin/llvm-ar", root) >=
            (int)sizeof fixture->ar) return false;
    if (snprintf(fixture->native, sizeof fixture->native, "%s/tools/native-cc", root) >=
        (int)sizeof fixture->native) return false;
    char script[1024];
    int n = snprintf(script, sizeof script,
        "#!/bin/sh\ncase \"${1:-}\" in -dumpmachine) printf 'x86_64-linux-gnu\\n'; exit 0;; esac\n"
        "exec '%s' \"$@\"\n", fixture->native);
    if (n <= 0 || n >= (int)sizeof script || !write_file(fixture->cc, script)) return false;
    n = snprintf(script, sizeof script,
        "#!/bin/sh\ncase \"${1:-}\" in -dumpmachine) printf 'x86_64-unknown-linux-gnu\\n'; exit 0;; esac\n"
        "exec '%s' \"$@\"\n", fixture->native);
    return n > 0 && n < (int)sizeof script && write_file(fixture->clang, script) &&
           write_file(fixture->ar, "#!/bin/sh\nexit 0\n");
}

static bool native_machine_case(const char *root)
{
    struct native_machine_fixture fixture;
    if (!native_machine_setup(root, &fixture)) return false;
    char path[PATH_MAX + 64];
    const char *home = getenv("HOME");
    if (!home || snprintf(path, sizeof path, "%s:%s:/usr/bin:/bin", fixture.tools,
                          fixture.bins) >= (int)sizeof path) return false;
    struct result result = {0};
    if (!run_build(root, fixture.clang, path, home, "llvm-ar", "libtor_stub.a", false,
                   &result) || !failed(&result)) return false;
    if (!strstr(result.output, "vendor/tor_stub.c missing (tracked source expected)")) {
        fprintf(stderr, "native Clang machine spelling treated as cross compiler: %s\n",
                result.output);
        return false;
    }
    (void)unlink(fixture.cc); (void)unlink(fixture.clang); (void)unlink(fixture.ar);
    return true;
}

static void run_lock_child(const char *root, const char *hostcc, const char *held,
                           const char *key, const char *lockdir, int read_fd, int write_fd)
{
    (void)close(read_fd);
    if (chdir(root) != 0 || dup2(write_fd, STDOUT_FILENO) < 0 ||
        dup2(write_fd, STDERR_FILENO) < 0) _exit(126);
    (void)close(write_fd);
    if (setenv("ZCL_VENDOR_OFFLINE", "1", 1)) _exit(125);
    if (hostcc && setenv("HOSTCC", hostcc, 1)) _exit(125);
    if (held && setenv("VENDOR_LOCK_HELD", held, 1)) _exit(125);
    if (key && setenv("VENDOR_LOCK_HELPER_KEY", key, 1)) _exit(125);
    if (lockdir && setenv("VENDOR_LOCK_DIR", lockdir, 1)) _exit(125);
    execl("tools/scripts/build_vendor.sh", "tools/scripts/build_vendor.sh",
          "libz.a", (char *)NULL);
    _exit(127);
}

static bool run_lock(const char *root, const char *hostcc, const char *held,
                     const char *key, const char *lockdir, struct result *result)
{
    int fds[2];
    if (pipe(fds) != 0) return false;
    pid_t child = fork();
    if (child == 0)
        run_lock_child(root, hostcc, held, key, lockdir, fds[0], fds[1]);
    (void)close(fds[1]);
    if (child < 0) { (void)close(fds[0]); return false; }
    bool drained = drain(fds[0], result);
    pid_t got;
    do { got = waitpid(child, &result->status, 0); } while (got < 0 && errno == EINTR);
    return drained && got == child;
}

static bool run_command(char *const argv[])
{
    pid_t child = fork();
    if (child == 0) { execvp(argv[0], argv); _exit(127); }
    if (child < 0) return false;
    int status = 0;
    pid_t got;
    do { got = waitpid(child, &status, 0); } while (got < 0 && errno == EINTR);
    return got == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool path_join(char *out, size_t size, const char *root, const char *name)
{
    return snprintf(out, size, "%s/%s", root, name) < (int)size;
}

static bool expect_lock(const char *root, const char *hostcc, const char *held,
                        const char *key, const char *lockdir, const char *expected)
{
    struct result result = {0};
    if (!run_lock(root, hostcc, held, key, lockdir, &result) || !failed(&result))
        return false;
    if (!strstr(result.output, expected)) {
        fprintf(stderr, "vendor lock expected [%s], got: %s\n", expected, result.output);
        return false;
    }
    return true;
}

static bool c_only_compiler_case(const char *root, const char *native, const char *c_only)
{
    char script[2048];
    int n = snprintf(script, sizeof script,
        "#!/bin/sh\nprevious=\"\"\nfor argument in \"$@\"; do\n"
        "    if [ \"$previous\" = -x ] && [ \"$argument\" = c++ ]; then\n"
        "        printf 'cc: fatal error: cannot execute cc1plus\\n' >&2\n"
        "        exit 1\n"
        "    fi\n"
        "    previous=\"$argument\"\n"
        "done\n"
        "exec '%s' \"$@\"\n", native);
    return n > 0 && n < (int)sizeof script && write_file(c_only, script) &&
           expect_lock(root, "tools/c-only-cc", NULL, NULL, NULL,
                       "offline cache miss or checksum failure: zlib-1.3.1.tar.gz");
}

static bool bootstrap_identity_case(const char *root, char *helper, char *cache,
                                    const char *before, const char *key_driver,
                                    const char *provenance, const char *prov_before)
{
    return run_command((char *[]){"cp", "-R", helper, cache, NULL}) &&
           copy_file(key_driver, before) && write_file(key_driver, "#!/bin/sh\nexit 0\n") &&
           expect_lock(root, NULL, NULL, NULL, NULL, "vendor lock compiler identity invalid") &&
           copy_file(before, key_driver) && copy_file(provenance, prov_before);
}

static bool source_hash_cases(const char *root, char *helper, char *cache,
                              const char *provenance, const char *prov_before)
{
    for (unsigned i = 0; i < 2; ++i) {
        if (!copy_file(prov_before, provenance)) return false;
        FILE *f = fopen(provenance, "a");
        if (!f) return false;
        int n = fprintf(f, "\nvp_sha256_file() { return %u; }\n", i == 0);
        if (n < 0 || fclose(f) != 0) return false;
        if (!expect_lock(root, NULL, NULL, NULL, NULL, "vendor lock source hash")) return false;
    }
    return copy_file(prov_before, provenance) &&
           run_command((char *[]){"diff", "-r", cache, helper, NULL});
}

static bool legacy_helper_key(const char *helper_root, char key[65])
{
    found_helper[0] = '\0';
    if (nftw(helper_root, helper_visit, 16, FTW_PHYS) != 1 || !found_helper[0])
        return false;
    char helper_path[PATH_MAX];
    int n = snprintf(helper_path, sizeof helper_path, "%s", found_helper);
    if (n <= 0 || n >= (int)sizeof helper_path) return false;
    char *slash = strrchr(helper_path, '/');
    if (!slash) return false;
    *slash = '\0';
    char *name = strrchr(helper_path, '/');
    if (!name) return false;
    ++name;
    if (strlen(name) != 64 || strspn(name, "0123456789abcdef") != 64) return false;
    memcpy(key, name, 65);
    return true;
}

static bool unknown_legacy_lock_case(const char *root)
{
    char helper_root[PATH_MAX], unknown[PATH_MAX], key[65];
    if (!path_join(helper_root, sizeof helper_root, root, "build/bin/vendor-lock") ||
        !path_join(unknown, sizeof unknown, root, "unknown-legacy.lock") ||
        mkdir(unknown, 0700) != 0) return false;
    if (!legacy_helper_key(helper_root, key)) return false;
    if (!expect_lock(root, NULL, "1", key, unknown, "vendor_lock_legacy_directory_refused"))
        return false;
    struct stat st;
    return stat(unknown, &st) == 0 && S_ISDIR(st.st_mode);
}

static bool extended_compiler_cases(const char *root)
{
    char native[PATH_MAX], c_only[PATH_MAX], before[PATH_MAX], key_driver[PATH_MAX];
    if (!path_join(native, sizeof native, root, "tools/native-cc") ||
        !path_join(c_only, sizeof c_only, root, "tools/c-only-cc") ||
        !path_join(before, sizeof before, root, "key-driver-before") ||
        !path_join(key_driver, sizeof key_driver, root, "tools/dev/build-epoch-key.sh"))
        return false;
    fprintf(stderr, "vendor extended: C-only compiler\n");
    if (!c_only_compiler_case(root, native, c_only)) return false;

    char helper[PATH_MAX], cache[PATH_MAX], provenance[PATH_MAX], prov_before[PATH_MAX];
    if (!path_join(helper, sizeof helper, root, "build/bin/vendor-lock") ||
        !path_join(cache, sizeof cache, root, "helper-cache-before") ||
        !path_join(provenance, sizeof provenance, root, "tools/scripts/vendor_provenance_lib.sh") ||
        !path_join(prov_before, sizeof prov_before, root, "provenance-before")) return false;
    fprintf(stderr, "vendor extended: bootstrap identity\n");
    if (!bootstrap_identity_case(root, helper, cache, before, key_driver, provenance,
                                 prov_before)) return false;
    fprintf(stderr, "vendor extended: source hashes\n");
    if (!source_hash_cases(root, helper, cache, provenance, prov_before)) return false;
    fprintf(stderr, "vendor extended: unknown legacy lock\n");
    return unknown_legacy_lock_case(root);
}

struct compiler_fixture {
    char path_cc[PATH_MAX], ar[128], paths[PATH_MAX + 64];
    const char *home;
};

static bool path_compiler_case(const char *root, const char *machine,
                               struct compiler_fixture *fixture)
{
    char tools[PATH_MAX], log_cc[4096];
    if (snprintf(tools, sizeof tools, "%s/tools", root) >= (int)sizeof tools ||
        snprintf(fixture->path_cc, sizeof fixture->path_cc, "%s/tools/path-cc", root) >=
            (int)sizeof fixture->path_cc ||
        snprintf(log_cc, sizeof log_cc, "%s/tools/native-cc", root) >= (int)sizeof log_cc)
        return false;
    char script[1024], logfile[PATH_MAX];
    if (snprintf(logfile, sizeof logfile, "%s/path-cc.log", root) >= (int)sizeof logfile)
        return false;
    int n = snprintf(script, sizeof script,
        "#!/bin/sh\nprintf '%%s\\n' \"$VENDOR_CC\" \"$PATH\" > '%s'\nexec '%s' \"$@\"\n",
        logfile, log_cc);
    if (n <= 0 || n >= (int)sizeof script || !write_file(fixture->path_cc, script)) return false;
    fixture->home = getenv("HOME");
    if (!fixture->home || snprintf(fixture->ar, sizeof fixture->ar, "%s-ar", machine) >=
            (int)sizeof fixture->ar ||
        snprintf(fixture->paths, sizeof fixture->paths, "%s/bin:/usr/bin:/bin", root) >=
            (int)sizeof fixture->paths) return false;
    return probe(root, fixture->path_cc, fixture->paths, fixture->home, fixture->ar,
                 "path-cc", tools, false);
}

struct external_fixture {
    char outside[PATH_MAX], home_cc[PATH_MAX], bin_cc[PATH_MAX];
    char out_home[PATH_MAX], out_bin[PATH_MAX], out_home_bin[PATH_MAX];
};

static const char *external_tmpdir(void)
{
    const char *tmpdir = getenv("TMPDIR");
    const char *home_root = getenv("HOME");
    if (!tmpdir || !*tmpdir || (home_root && path_under(tmpdir, home_root))) {
#ifdef P_tmpdir
        tmpdir = P_tmpdir;
#else
        fputs("a platform temporary directory is required for the external compiler fixture\n",
              stderr);
        return NULL;
#endif
    }
    return tmpdir;
}

static bool external_fixture_setup(struct external_fixture *fixture, const char *path_cc)
{
    if (snprintf(fixture->out_home, sizeof fixture->out_home, "%s/%s", fixture->outside,
                 "home") >= (int)sizeof fixture->out_home ||
        snprintf(fixture->out_bin, sizeof fixture->out_bin, "%s/bin", fixture->outside) >=
            (int)sizeof fixture->out_bin ||
        snprintf(fixture->out_home_bin, sizeof fixture->out_home_bin, "%s/%s",
                 fixture->out_home, "bin") >= (int)sizeof fixture->out_home_bin) return false;
    if (mkdir(fixture->out_home, 0700) != 0 || mkdir(fixture->out_home_bin, 0700) != 0 ||
        mkdir(fixture->out_bin, 0700) != 0) { perror("mkdir"); return false; }
    if (snprintf(fixture->home_cc, sizeof fixture->home_cc, "%s/path-cc",
                 fixture->out_home_bin) >= (int)sizeof fixture->home_cc ||
        snprintf(fixture->bin_cc, sizeof fixture->bin_cc, "%s/path-cc", fixture->out_bin) >=
            (int)sizeof fixture->bin_cc) return false;
    return copy_file(path_cc, fixture->home_cc) && copy_file(path_cc, fixture->bin_cc);
}

static bool external_fixture_probes(const char *root, const struct compiler_fixture *compiler,
                                    const struct external_fixture *fixture)
{
    bool ok = probe(root, fixture->home_cc, compiler->paths, fixture->out_home, compiler->ar,
                    "path-cc", fixture->out_home_bin, false);
    if (interrupted || !ok) return false;
    ok = probe(root, fixture->bin_cc, compiler->paths, compiler->home, compiler->ar,
               fixture->bin_cc, fixture->out_bin, true);
    if (interrupted || !ok) return false;
    ok = native_machine_case(root);
    if (interrupted || !ok) return false;
    return extended_compiler_cases(root);
}

static void external_fixture_cleanup(const struct external_fixture *fixture)
{
    (void)unlink(fixture->home_cc); (void)unlink(fixture->bin_cc);
    (void)rmdir(fixture->out_home_bin); (void)rmdir(fixture->out_home);
    (void)rmdir(fixture->out_bin); (void)rmdir(fixture->outside);
}

static bool external_compiler_cases(const char *root, const struct compiler_fixture *compiler)
{
    const char *tmpdir = external_tmpdir();
    if (!tmpdir) return false;
    struct external_fixture fixture = {0};
    if (snprintf(fixture.outside, sizeof fixture.outside, "%s/zcl-vendor-outside.XXXXXX",
                 tmpdir) >= (int)sizeof fixture.outside) return false;
    if (!mkdtemp(fixture.outside)) { perror("mkdtemp"); return false; }
    bool ok = external_fixture_setup(&fixture, compiler->path_cc);
    if (ok) ok = external_fixture_probes(root, compiler, &fixture);
    external_fixture_cleanup(&fixture);
    return ok && !interrupted;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: vendor_compiler_selftest SANDBOX FIXTURE_MACHINE\n");
        return 2;
    }
    const char *root = argv[1];
    struct compiler_fixture fixture;
    if (!path_compiler_case(root, argv[2], &fixture)) return 1;
    if (signal(SIGHUP, note_interrupt) == SIG_ERR ||
        signal(SIGINT, note_interrupt) == SIG_ERR ||
        signal(SIGTERM, note_interrupt) == SIG_ERR) return 1;
    if (!external_compiler_cases(root, &fixture)) return 1;
    puts("vendor_compiler_selftest: PASS");
    return 0;
}
