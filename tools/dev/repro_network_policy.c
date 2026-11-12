/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Prove the Makefile parse barrier and repro-verify force offline,
 *          cache-free, locale-pinned child builds. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "repro_network_policy.h"

#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define RNP_PATH 4096

static const char k_funcs[] =
    "make()\n"
    "{\n"
    "    local arg build_dir=build binary=zclassic23\n"
    "    if [[ \" $* \" == *' __zcl_repro_capture '* ]]; then\n"
    "        case \"${ZCL_REPRO_CAPTURE_NAME:-}\" in\n"
    "            CFLAGS)\n"
    "                printf '%s\\n' '-std=c23 -O2 -march=native -Iexpanded/include' \\\n"
    "                    >\"$ZCL_REPRO_CAPTURE_PATH\"\n"
    "                ;;\n"
    "            LDFLAGS)\n"
    "                printf '%s\\n' '-pthread -Wl,-z,now' >\"$ZCL_REPRO_CAPTURE_PATH\"\n"
    "                ;;\n"
    "            *) return 2 ;;\n"
    "        esac\n"
    "        return 0\n"
    "    fi\n"
    "    printf 'offline=%s ccache=%s locale=%s timezone=%s path=%s home=%s\\n' \\\n"
    "        \"${ZCL_VENDOR_OFFLINE:-unset}\" \"${ZCL_USE_CCACHE:-unset}\" \\\n"
    "        \"${LC_ALL:-unset}\" \"${TZ:-unset}\" \"${PATH:-unset}\" \\\n"
    "        \"${HOME:-unset}\" \\\n"
    "        >>\"$REPRO_POLICY_LOG\"\n"
    "    for arg in \"$@\"; do\n"
    "        case \"$arg\" in\n"
    "            BUILD_DIR=*) build_dir=\"${arg#BUILD_DIR=}\" ;;\n"
    "            zclassic23|zclassic-cli) binary=\"$arg\" ;;\n"
    "        esac\n"
    "    done\n"
    "    mkdir -p \"$build_dir/bin\"\n"
    "    if [ \"$binary\" = zclassic23 ]; then\n"
    "        printf 'repro-network-policy-fixture\\n' >\"$build_dir/bin/z23\"\n"
    "        ln -s z23 \"$build_dir/bin/zclassic23\"\n"
    "    else\n"
    "        printf 'repro-network-policy-fixture\\n' >\"$build_dir/bin/$binary\"\n"
    "    fi\n"
    "}\n"
    "git()\n"
    "{\n"
    "    if [[ \" $* \" == *' rev-parse --show-toplevel '* ]]; then\n"
    "        printf '%s\\n' \"$REPRO_FAKE_SOURCE\"\n"
    "    elif [[ \" $* \" == *' log -1 '* ]]; then\n"
    "        printf '%s\\n' '1700000000'\n"
    "    fi\n"
    "    return 0\n"
    "}\n"
    "rsync()\n"
    "{\n"
    "    local argc=$# src dst\n"
    "    local args=(\"$@\")\n"
    "    (( argc >= 2 )) || return 2\n"
    "    src=\"${args[argc - 2]}\"\n"
    "    dst=\"${args[argc - 1]}\"\n"
    "    mkdir -p \"$dst\"\n"
    "    if [[ -d \"${src%/./}\" ]]; then\n"
    "        cp -a \"${src%/./}/.\" \"$dst/\"\n"
    "    fi\n"
    "}\n"
    "readelf()\n"
    "{\n"
    "    printf 'unexpected ELF inspection of the policy fixture\\n' >&2\n"
    "    return 2\n"
    "}\n"
    "openssl()\n"
    "{\n"
    "    [[ $# == 3 && \"$1\" == dgst && \"$2\" == -sha3-256 ]] || return 2\n"
    "    /usr/bin/cmp -s \"$3\" \"$REPRO_EXPECTED_BINARY\" || return 2\n"
    "    printf 'SHA3-256(%s)= %s\\n' \"$3\" \\\n"
    "        bbc9a732fd210cc2404cb4b2a3245353191866808bf5a4f043b5ba1a5ae41df0\n"
    "}\n"
    "stat()\n"
    "{\n"
    "    [[ $# == 2 && \"$1\" == -Lc%s ]] || return 2\n"
    "    /usr/bin/wc -c < \"$2\"\n"
    "}\n";

static const char k_policy_tail[] =
    ".PHONY: ci-reproducible\n"
    "ci-reproducible:\n"
    "\t@printf '%s %s\\n' \"$(ZCL_VENDOR_OFFLINE)\" \"$(ZCL_USE_CCACHE)\"\n";

static const char k_hermetic[] =
    "offline=1 ccache=0 locale=C timezone=UTC path=/usr/bin:/bin home=/nonexistent\n";

static int rnp_check_log(const char *path);

static int rnp_fail(const char *msg)
{
    fprintf(stderr, "repro_network_policy_selftest: FAIL: %s\n", msg);
    return 1;
}

static int rnp_fail_value(const char *prefix, const char *value)
{
    fprintf(stderr, "repro_network_policy_selftest: FAIL: %s%s\n", prefix, value);
    return 1;
}

static int rnp_path(char *out, size_t cap, const char *dir, const char *leaf)
{
    size_t a = strlen(dir);
    size_t b = strlen(leaf);
    if (leaf[0] == '\0' || a + b + 2 > cap)
        return -1;
    memcpy(out, dir, a);
    out[a] = '/';
    memcpy(out + a + 1, leaf, b + 1);
    return 0;
}

static int rnp_status(pid_t child)
{
    int status = 0;
    pid_t got = -1;
    while (got < 0) {
        got = waitpid(child, &status, 0);
        if (got == child)
            break;
        if (errno != EINTR)
            return 125;
        got = -1;
    }
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    if (!WIFEXITED(status))
        return 125;
    return WEXITSTATUS(status);
}

static int rnp_run(char *const argv[], const char *out_path)
{
    pid_t child;
    int fd = -1;
    int rc;
    if (out_path != NULL) {
        fd = open(out_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
        if (fd < 0)
            return 127;
    }
    child = fork();
    if (child < 0) {
        if (fd >= 0)
            close(fd);
        return 127;
    }
    if (child == 0) {
        if (fd >= 0 && dup2(fd, STDOUT_FILENO) < 0)
            _exit(127);
        if (fd >= 0)
            close(fd);
        /* An outer make's jobserver and print flags must not reach this
         * independent probe's child make: inherited MAKEFLAGS/MFLAGS/
         * GNUMAKEFLAGS leak the parent's options ("--no-print-directory"
         * is ours; the parent's directory banners are not). */
        unsetenv("MAKEFLAGS");
        unsetenv("MFLAGS");
        unsetenv("GNUMAKEFLAGS");
        execvp(argv[0], argv);
        _exit(127);
    }
    if (fd >= 0)
        close(fd);
    rc = rnp_status(child);
    return rc;
}

static int rnp_rm(const char *path)
{
    char *argv[] = {"rm", "-rf", "--", (char *)path, NULL};
    pid_t child;
    if (path == NULL || strstr(path, "zcl-repro-network-selftest") == NULL)
        return -1;
    child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        execvp(argv[0], argv);
        _exit(126);
    }
    return rnp_status(child) == 0 ? 0 : -1;
}

static int rnp_take_dir(int fd, char *out, size_t cap)
{
    size_t used = 0;
    if (out == NULL || cap < 2)
        return -1;
    while (used + 1 < cap) {
        ssize_t n = read(fd, out + used, cap - 1 - used);
        if (n == 0)
            break;
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            return -1;
        used += (size_t)n;
    }
    if (used > 0 && out[used - 1] == '\n')
        used--;
    out[used] = '\0';
    if (used == 0 || used + 1 >= cap)
        return -1;
    return 0;
}

static int rnp_mktemp_dir(char *const argv[], char *out, size_t cap)
{
    int fds[2];
    pid_t child;
    int took;
    int rc;
    if (pipe(fds) != 0)
        return 127;
    child = fork();
    if (child < 0) {
        close(fds[0]);
        close(fds[1]);
        return 127;
    }
    if (child == 0) {
        if (dup2(fds[1], STDOUT_FILENO) < 0)
            _exit(127);
        close(fds[0]);
        close(fds[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(fds[1]);
    took = rnp_take_dir(fds[0], out, cap);
    close(fds[0]);
    rc = rnp_status(child);
    if (rc != 0)
        return rc;
    return took == 0 ? 0 : 127;
}

static int rnp_sandbox(char *out, size_t cap)
{
    const char *tmp = getenv("TMPDIR");
    char templ[RNP_PATH];
    char *argv[] = {"mktemp", "-d", templ, NULL};
    if (tmp == NULL || tmp[0] == '\0')
        tmp = "/tmp";
    if (rnp_path(templ, sizeof templ, tmp, "zcl-repro-network-selftest.XXXXXX") != 0)
        return -1;
    return rnp_mktemp_dir(argv, out, cap);
}

static int rnp_put(const char *path, const char *text)
{
    FILE *fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    if (fputs(text, fp) < 0) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0)
        return -1;
    return 0;
}

static int rnp_mkdir(const char *path)
{
    if (mkdir(path, 0700) == 0 || errno == EEXIST)
        return 0;
    return -1;
}

static int rnp_read(const char *path, char *buf, size_t cap)
{
    FILE *fp = fopen(path, "r");
    size_t n;
    if (fp == NULL || cap < 2)
        return -1;
    n = fread(buf, 1, cap - 1, fp);
    fclose(fp);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        n--;
    buf[n] = '\0';
    return 0;
}

static int rnp_keep_capture(void)
{
    const char *name = getenv("ZCL_REPRO_CAPTURE_NAME");
    const char *path = getenv("ZCL_REPRO_CAPTURE_PATH");
    if (name != NULL && name[0] != '\0' && setenv("ZCL_REPRO_CAPTURE_NAME", name, 1) != 0)
        return -1;
    if (path != NULL && path[0] != '\0' && setenv("ZCL_REPRO_CAPTURE_PATH", path, 1) != 0)
        return -1;
    return 0;
}

static int rnp_starts(const char *line, const char *prefix)
{
    size_t n = strlen(prefix);
    return strncmp(line, prefix, n) == 0;
}

static int rnp_extract(const char *makefile, const char *out)
{
    FILE *in = fopen(makefile, "r");
    FILE *fp;
    char line[8192];
    int copying = 0;
    int wrote = 0;
    if (in == NULL)
        return -1;
    fp = fopen(out, "w");
    if (fp == NULL) {
        fclose(in);
        return -1;
    }
    while (fgets(line, sizeof line, in) != NULL) {
        if (!copying && rnp_starts(line, "ZCL_NETWORK_DENIED_BUILD_GOALS :="))
            copying = 1;
        if (!copying)
            continue;
        if (fputs(line, fp) < 0) {
            fclose(in);
            fclose(fp);
            return -1;
        }
        wrote = 1;
        if (strcmp(line, "endif\n") == 0)
            break;
    }
    fclose(in);
    if (!wrote || fputs(k_policy_tail, fp) < 0) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0)
        return -1;
    return 0;
}

static int rnp_find_line(const char *makefile, const char *prefix)
{
    FILE *fp = fopen(makefile, "r");
    char line[8192];
    int number = 0;
    if (fp == NULL)
        return 0;
    while (fgets(line, sizeof line, fp) != NULL) {
        number++;
        if (rnp_starts(line, prefix)) {
            fclose(fp);
            return number;
        }
    }
    fclose(fp);
    return 0;
}

static int rnp_order(const char *makefile)
{
    int policy = rnp_find_line(makefile, "ZCL_NETWORK_DENIED_BUILD_GOALS :=");
    int cache = rnp_find_line(makefile, "ZCL_USE_CCACHE ?=");
    int barrier = rnp_find_line(makefile, "VENDOR_BOOTSTRAP_MK :=");
    if (!(policy < cache))
        return rnp_fail("Make hermetic policy is defined after compiler-cache selection");
    if (!(policy < barrier))
        return rnp_fail("Make offline policy is defined after the vendor parse barrier");
    return 0;
}

static int rnp_make_policy(const char *policy_mk, const char *out_path)
{
    char *argv[] = {"/usr/bin/make", "--no-print-directory", "-s", "-f",
                    (char *)policy_mk, "ZCL_VENDOR_OFFLINE=0", "ZCL_USE_CCACHE=1",
                    "ci-reproducible", NULL};
    char value[256];
    int rc = rnp_run(argv, out_path);
    if (rc != 0)
        return rc;
    if (rnp_read(out_path, value, sizeof value) != 0)
        return rnp_fail("Make parse barrier did not force offline/no-cache policy: ");
    if (strcmp(value, "1 0") != 0)
        return rnp_fail_value("Make parse barrier did not force offline/no-cache policy: ",
                              value);
    return 0;
}

static int rnp_write_driver(const char *path, const char *funcs, const char *log,
                            const char *expected, const char *fake, const char *different,
                            const char *verify, const char *repro_log)
{
    FILE *fp = fopen(path, "w");
    int nw;
    if (fp == NULL)
        return -1;
    nw = fprintf(fp,
                 "#!/usr/bin/env bash\n"
                 "set -euo pipefail\n"
                 "source '%s'\n"
                 "export -f make git rsync readelf openssl stat\n"
                 "export REPRO_POLICY_LOG='%s'\n"
                 "export REPRO_EXPECTED_BINARY='%s'\n"
                 "export REPRO_FAKE_SOURCE='%s'\n"
                 "if openssl dgst -sha3-256 '%s' >/dev/null 2>&1; then\n"
                 "  printf 'repro_network_policy_selftest: FAIL: fixture digest accepted different bytes\\n' >&2\n"
                 "  exit 1\n"
                 "fi\n"
                 "cd '%s'\n"
                 "export ZCL_VENDOR_OFFLINE=0\n"
                 "export PATH=/usr/bin:/bin\n"
                 "export ZCL_REPRO_JOBS=1\n"
                 "bash '%s' >'%s' 2>&1\n",
                 funcs, log, expected, fake, different, fake, verify, repro_log);
    if (nw < 0) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0)
        return -1;
    return 0;
}

static int rnp_show_log(const char *path)
{
    FILE *fp = fopen(path, "r");
    char buf[1024];
    size_t n;
    if (fp == NULL)
        return 0;
    while ((n = fread(buf, 1, sizeof buf, fp)) > 0) {
        if (fwrite(buf, 1, n, stderr) != n) {
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);
    return 0;
}

static int rnp_child(const char *sandbox, const char *verify)
{
    char funcs[RNP_PATH];
    char driver[RNP_PATH];
    char log[RNP_PATH];
    char expected[RNP_PATH];
    char different[RNP_PATH];
    char source[RNP_PATH];
    char repro_log[RNP_PATH];
    char *argv[] = {"bash", driver, NULL};
    int rc;
    if (rnp_path(funcs, sizeof funcs, sandbox, "funcs.sh") != 0)
        return 1;
    if (rnp_path(driver, sizeof driver, sandbox, "driver.sh") != 0)
        return 1;
    if (rnp_path(log, sizeof log, sandbox, "build-policy.log") != 0)
        return 1;
    if (rnp_path(expected, sizeof expected, sandbox, "expected-binary") != 0)
        return 1;
    if (rnp_path(different, sizeof different, sandbox, "different-binary") != 0)
        return 1;
    if (rnp_path(source, sizeof source, sandbox, "source") != 0)
        return 1;
    if (rnp_path(repro_log, sizeof repro_log, sandbox, "repro.log") != 0)
        return 1;
    if (rnp_put(funcs, k_funcs) != 0 || rnp_put(log, "") != 0)
        return 1;
    if (rnp_put(expected, "repro-network-policy-fixture\n") != 0)
        return 1;
    if (rnp_put(different, "different-policy-fixture\n") != 0)
        return 1;
    if (rnp_mkdir(source) != 0)
        return 1;
    if (rnp_write_driver(driver, funcs, log, expected, source, different, verify,
                         repro_log) != 0)
        return 1;
    rc = rnp_run(argv, NULL);
    if (rc != 0) {
        rnp_show_log(repro_log);
        return rnp_fail("repro-verify fixture failed");
    }
    return rnp_check_log(log);
}

static int rnp_check_log(const char *path)
{
    FILE *fp = fopen(path, "r");
    char line[512];
    int count = 0;
    char got[64];
    if (fp == NULL)
        return rnp_fail("expected two observed child builds, got 0");
    while (fgets(line, sizeof line, fp) != NULL) {
        count++;
        if (strcmp(line, k_hermetic) != 0) {
            fclose(fp);
            return rnp_fail("a child build inherited non-hermetic execution policy");
        }
    }
    fclose(fp);
    if (count == 2)
        return 0;
    if (snprintf(got, sizeof got, "%d", count) < 0)
        return 1;
    return rnp_fail_value("expected two observed child builds, got ", got);
}

static int rnp_abs(const char *path, char *out, size_t cap)
{
    char cwd[PATH_MAX];
    size_t nc;
    size_t np = strlen(path);
    if (path[0] == '/') {
        if (np + 1 > cap)
            return -1;
        memcpy(out, path, np + 1);
        return 0;
    }
    if (getcwd(cwd, sizeof cwd) == NULL)
        return -1;
    nc = strlen(cwd);
    if (nc + np + 2 > cap)
        return -1;
    memcpy(out, cwd, nc);
    out[nc] = '/';
    memcpy(out + nc + 1, path, np + 1);
    return 0;
}

static int rnp_body(const char *repo, const char *sandbox)
{
    char makefile[RNP_PATH];
    char verify_rel[RNP_PATH];
    char verify[RNP_PATH];
    char policy[RNP_PATH];
    char make_out[RNP_PATH];
    int rc;
    if (rnp_path(makefile, sizeof makefile, repo, "Makefile") != 0)
        return 1;
    if (rnp_path(policy, sizeof policy, sandbox, "network-policy.mk") != 0)
        return 1;
    if (rnp_path(make_out, sizeof make_out, sandbox, "make.out") != 0)
        return 1;
    if (rnp_extract(makefile, policy) != 0)
        return rnp_fail("could not extract the network-denied Make policy");
    rc = rnp_make_policy(policy, make_out);
    if (rc != 0)
        return rc;
    rc = rnp_order(makefile);
    if (rc != 0)
        return rc;
    if (rnp_path(verify_rel, sizeof verify_rel, repo, "tools/scripts/repro-verify.sh") != 0)
        return 1;
    if (rnp_abs(verify_rel, verify, sizeof verify) != 0)
        return rnp_fail("repro-verify fixture failed");
    return rnp_child(sandbox, verify);
}

static int rnp_dispatch(const char *repo)
{
    char sandbox[RNP_PATH];
    int rc;
    if (repo == NULL || repo[0] == '\0')
        return rnp_fail("repo is required");
    if (strchr(repo, '\'') != NULL)
        return rnp_fail("repo path is not safe to quote");
    if (rnp_keep_capture() != 0)
        return 1;
    if (rnp_sandbox(sandbox, sizeof sandbox) != 0)
        return rnp_fail("could not create the policy sandbox");
    rc = rnp_body(repo, sandbox);
    rnp_rm(sandbox);
    if (rc != 0)
        return rc;
    printf("repro_network_policy_selftest: PASS builds=2 make_parse_offline=true "
           "make_parse_cache=false host_cache=false\n");
    return 0;
}

#endif /* !_WIN32 */

int zcl_repro_network_policy(const char *repo)
{
#if defined(_WIN32)
    (void)repo;
    fprintf(stdout, "repro_network_policy_selftest: unavailable on Windows\n");
    return 2;
#else
    return rnp_dispatch(repo);
#endif
}
