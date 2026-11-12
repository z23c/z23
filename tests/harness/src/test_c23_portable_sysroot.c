/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Drive zcl_c23_portable_sysroot through prepare, verify, fetch,
 *          and sysroot link repair against stub tools. */

#include "test/test_core.h"

#include "c23_portable_sysroot.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char k_hash[] =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char k_tool[] = "build/toolchains/debian-bullseye-glibc-2.31-amd64";
static const char k_deb[] = "libc6_2.31-13+deb11u14_amd64.deb";
static const char k_debs[][48] = {
    "libc6_2.31-13+deb11u14_amd64.deb",
    "libc6-dev_2.31-13+deb11u14_amd64.deb",
    "linux-libc-dev_6.1.176-1_amd64.deb",
};

static int cps_put(const char *path, const char *text)
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

static int cps_read(const char *path, char *buf, size_t cap)
{
    FILE *fp = fopen(path, "r");
    size_t n;
    if (fp == NULL)
        return -1;
    n = fread(buf, 1, cap - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    return 0;
}

static int cps_mkdir_one(const char *path)
{
    if (mkdir(path, 0700) == 0 || errno == EEXIST)
        return 0;
    return -1;
}

static int cps_mkdir_at(const char *dir, const char *rel)
{
    char path[PATH_MAX];
    size_t n;
    size_t i;
    if (snprintf(path, sizeof path, "%s/%s", dir, rel) >= (int)sizeof path)
        return -1;
    n = strlen(path);
    for (i = 1; i < n; i++) {
        if (path[i] != '/')
            continue;
        path[i] = '\0';
        if (cps_mkdir_one(path) != 0)
            return -1;
        path[i] = '/';
    }
    return cps_mkdir_one(path);
}

static int cps_rel(const char *dir, const char *rel, char *out, size_t cap)
{
    int nw = snprintf(out, cap, "%s/%s", dir, rel);
    if (nw < 0 || (size_t)nw >= cap)
        return -1;
    return 0;
}

static int cps_link(const char *dir, const char *leaf)
{
    char target[PATH_MAX];
    char dest[PATH_MAX];
    if (cps_rel(dir, "record.sh", target, sizeof target) != 0)
        return -1;
    if (snprintf(dest, sizeof dest, "%s/bin/%s", dir, leaf) >= (int)sizeof dest)
        return -1;
    if (symlink(target, dest) != 0)
        return -1;
    return 0;
}

static int cps_write_script(const char *dir)
{
    char body[8192];
    char path[PATH_MAX];
    int nw = snprintf(
        body, sizeof body,
        "#!/bin/sh\n"
        "dir='%s'\n"
        "base=${0##*/}\n"
        "{\n"
        "  printf '%%s' \"$base\"\n"
        "  for a in \"$@\"; do printf ' [%%s]' \"$a\"; done\n"
        "  printf '\\n'\n"
        "} >> \"$dir/log\"\n"
        "case \"$base\" in\n"
        "  sha256sum)\n"
        "    if [ \"${1-}\" = -c ]; then\n"
        "      if [ -f \"$dir/sha.fail\" ]; then exit 1; fi\n"
        "      exit 0\n"
        "    fi\n"
        "    printf '%%s\\n' '%s  -'\n"
        "    ;;\n"
        "  objdump)\n"
        "    if [ -f \"$dir/objdump.out\" ]; then\n"
        "      while IFS= read -r line || [ -n \"${line-}\" ]; do\n"
        "        printf '%%s\\n' \"$line\"\n"
        "      done < \"$dir/objdump.out\"\n"
        "    else\n"
        "      printf '%%s\\n' GLIBC_2.31\n"
        "    fi\n"
        "    ;;\n"
        "  curl|wget)\n"
        "    out=\n"
        "    prev=\n"
        "    for a in \"$@\"; do\n"
        "      if [ \"$prev\" = -o ] || [ \"$prev\" = -O ]; then out=$a; fi\n"
        "      prev=$a\n"
        "    done\n"
        "    printf 'fetched\\n' > \"$out\"\n"
        "    ;;\n"
        "  \"cc tool\")\n"
        "    if [ -f \"$dir/cc.fail\" ]; then exit 7; fi\n"
        "    out=\n"
        "    prev=\n"
        "    saw=\n"
        "    for a in \"$@\"; do\n"
        "      if [ \"$prev\" = -o ]; then out=$a; fi\n"
        "      if [ \"$a\" = -dM ]; then saw=1; fi\n"
        "      prev=$a\n"
        "    done\n"
        "    if [ -n \"$out\" ]; then\n"
        "      printf '%%s\\n' '#!/bin/sh' 'exit 0' > \"$out\"\n"
        "      chmod 0755 \"$out\"\n"
        "    fi\n"
        "    if [ \"$saw\" = 1 ] && [ -f \"$dir/macros\" ]; then\n"
        "      while IFS= read -r line || [ -n \"${line-}\" ]; do\n"
        "        printf '%%s\\n' \"$line\"\n"
        "      done < \"$dir/macros\"\n"
        "    fi\n"
        "    ;;\n"
        "  ar)\n"
        "    printf 'deb\\n'\n"
        "    ;;\n"
        "  tar)\n"
        "    dest=.\n"
        "    prev=\n"
        "    for a in \"$@\"; do\n"
        "      if [ \"$prev\" = -C ]; then dest=$a; fi\n"
        "      prev=$a\n"
        "    done\n"
        "    cat >/dev/null\n"
        "    mkdir -p \"$dest/lib64\" \"$dest/usr/lib/x86_64-linux-gnu\" \"$dest/usr/include\"\n"
        "    ln -s /abs/loader \"$dest/lib64/ld-linux-x86-64.so.2\"\n"
        "    ln -s /lib/x86_64-linux-gnu/libfoo.so.1 "
        "\"$dest/usr/lib/x86_64-linux-gnu/libfoo.so\"\n"
        "    ln -s libfoo.so.1 \"$dest/usr/lib/x86_64-linux-gnu/libkeep.so\"\n"
        "    printf 'x' > \"$dest/usr/lib/x86_64-linux-gnu/notlink.so\"\n"
        "    printf 'h' > \"$dest/usr/include/stdio.h\"\n"
        "    printf 'o' > \"$dest/usr/lib/x86_64-linux-gnu/crt1.o\"\n"
        "    ;;\n"
        "esac\n"
        "exit 0\n",
        dir, k_hash);
    if (nw < 0 || (size_t)nw >= sizeof body)
        return -1;
    if (cps_rel(dir, "record.sh", path, sizeof path) != 0)
        return -1;
    if (cps_put(path, body) != 0)
        return -1;
    if (chmod(path, 0755) != 0)
        return -1;
    return 0;
}

static int cps_arm(const char *dir)
{
    static const char *k_leaves[] = {"sha256sum", "objdump", "ar", "tar", NULL};
    int i;
    if (strchr(dir, '\'') != NULL)
        return -1;
    if (cps_mkdir_at(dir, "bin") != 0)
        return -1;
    if (cps_write_script(dir) != 0)
        return -1;
    for (i = 0; k_leaves[i] != NULL; i++) {
        if (cps_link(dir, k_leaves[i]) != 0)
            return -1;
    }
    if (cps_link(dir, "cc tool") != 0)
        return -1;
    return 0;
}

static int cps_cc_path(const char *dir, char *out, size_t cap)
{
    return cps_rel(dir, "bin/cc tool", out, cap);
}

static int cps_sysroot(const char *dir, char *out, size_t cap)
{
    char rel[PATH_MAX];
    if (snprintf(rel, sizeof rel, "%s/root", k_tool) >= (int)sizeof rel)
        return -1;
    return cps_rel(dir, rel, out, cap);
}

static int cps_plant_fresh(const char *dir)
{
    char rel[PATH_MAX];
    char path[PATH_MAX];
    char text[80];
    if (snprintf(text, sizeof text, "%s\n", k_hash) >= (int)sizeof text)
        return -1;
    if (snprintf(rel, sizeof rel, "%s/inputs.sha256", k_tool) >= (int)sizeof rel)
        return -1;
    if (cps_mkdir_at(dir, k_tool) != 0)
        return -1;
    if (cps_rel(dir, rel, path, sizeof path) != 0 || cps_put(path, text) != 0)
        return -1;
    if (snprintf(rel, sizeof rel, "%s/root/usr/include/stdio.h", k_tool) >= (int)sizeof rel)
        return -1;
    if (cps_mkdir_at(dir, "build/toolchains/debian-bullseye-glibc-2.31-amd64/root/usr/include") != 0)
        return -1;
    if (cps_rel(dir, rel, path, sizeof path) != 0 || cps_put(path, "int\n") != 0)
        return -1;
    if (snprintf(rel, sizeof rel, "%s/root/usr/lib/x86_64-linux-gnu/crt1.o", k_tool) >=
        (int)sizeof rel)
        return -1;
    if (cps_mkdir_at(dir, "build/toolchains/debian-bullseye-glibc-2.31-amd64/root/usr/lib/x86_64-linux-gnu") != 0)
        return -1;
    if (cps_rel(dir, rel, path, sizeof path) != 0 || cps_put(path, "o\n") != 0)
        return -1;
    return 0;
}

static int cps_plant_debs(const char *dir)
{
    char rel[PATH_MAX];
    char path[PATH_MAX];
    int i;
    if (snprintf(rel, sizeof rel, "%s/downloads", k_tool) >= (int)sizeof rel)
        return -1;
    if (cps_mkdir_at(dir, rel) != 0)
        return -1;
    for (i = 0; i < 3; i++) {
        if (snprintf(rel, sizeof rel, "%s/downloads/%s", k_tool, k_debs[i]) >= (int)sizeof rel)
            return -1;
        if (cps_rel(dir, rel, path, sizeof path) != 0 || cps_put(path, "deb\n") != 0)
            return -1;
    }
    return 0;
}

static int cps_capture(const char *scratch, const char *repo, const char *mode, char *out,
                       size_t out_cap, char *err, size_t err_cap)
{
    char out_path[PATH_MAX];
    char err_path[PATH_MAX];
    int saved_out = -1;
    int saved_err = -1;
    int fd_out = -1;
    int fd_err = -1;
    int rc;
    if (snprintf(out_path, sizeof out_path, "%s/stdout.txt", scratch) >= (int)sizeof out_path)
        return -1;
    if (snprintf(err_path, sizeof err_path, "%s/stderr.txt", scratch) >= (int)sizeof err_path)
        return -1;
    fflush(stdout);
    fflush(stderr);
    saved_out = dup(STDOUT_FILENO);
    saved_err = dup(STDERR_FILENO);
    fd_out = open(out_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    fd_err = open(err_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (saved_out < 0 || saved_err < 0 || fd_out < 0 || fd_err < 0)
        goto fail;
    if (dup2(fd_out, STDOUT_FILENO) < 0 || dup2(fd_err, STDERR_FILENO) < 0)
        goto fail;
    rc = zcl_c23_portable_sysroot(repo, mode);
    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
    close(fd_out);
    close(fd_err);
    if (cps_read(out_path, out, out_cap) != 0 || cps_read(err_path, err, err_cap) != 0)
        return -1;
    return rc;
fail:
    if (saved_out >= 0) {
        dup2(saved_out, STDOUT_FILENO);
        close(saved_out);
    }
    if (saved_err >= 0) {
        dup2(saved_err, STDERR_FILENO);
        close(saved_err);
    }
    if (fd_out >= 0)
        close(fd_out);
    if (fd_err >= 0)
        close(fd_err);
    return -1;
}

static int cps_bind(const char *dir, const char *cc, int closed, char *old_path, size_t cap)
{
    const char *saved = getenv("PATH");
    char next[PATH_MAX];
    if (saved == NULL)
        saved = "";
    if (strlen(saved) + 1 > cap)
        return -1;
    memcpy(old_path, saved, strlen(saved) + 1);
    if (closed) {
        if (snprintf(next, sizeof next, "%s/bin", dir) >= (int)sizeof next)
            return -1;
    } else if (snprintf(next, sizeof next, "%s/bin:/usr/bin:/bin", dir) >= (int)sizeof next) {
        return -1;
    }
    if (setenv("PATH", next, 1) != 0)
        return -1;
    if (cc == NULL || cc[0] == '\0') {
        unsetenv("ZCL_PORTABLE_CC");
        return 0;
    }
    if (setenv("ZCL_PORTABLE_CC", cc, 1) != 0)
        return -1;
    return 0;
}

static void cps_unbind(const char *old_path)
{
    if (setenv("PATH", old_path, 1) != 0)
        return;
    unsetenv("ZCL_PORTABLE_CC");
}

static int cps_drive(const char *dir, const char *cc, const char *mode, int closed,
                     char *out, size_t out_cap, char *err, size_t err_cap)
{
    char old[8192];
    int rc;
    if (cps_bind(dir, cc, closed, old, sizeof old) != 0)
        return -1;
    rc = cps_capture(dir, dir, mode, out, out_cap, err, err_cap);
    cps_unbind(old);
    return rc;
}

static int cps_case(const char *root, const char *tag, char *dir, size_t cap)
{
    if (snprintf(dir, cap, "%s/%s", root, tag) >= (int)cap)
        return -1;
    if (mkdir(dir, 0700) != 0)
        return -1;
    if (cps_arm(dir) != 0)
        return -1;
    return 0;
}

static int cps_plant_macros(const char *dir, size_t bytes)
{
    char path[PATH_MAX];
    FILE *fp;
    size_t n = 0;
    int i = 0;
    if (cps_rel(dir, "macros", path, sizeof path) != 0)
        return -1;
    fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    while (n < bytes) {
        char line[64];
        int nw = snprintf(line, sizeof line, "#define HARMLESS_%d 1\n", i);
        if (nw < 0 || fputs(line, fp) < 0) {
            fclose(fp);
            return -1;
        }
        n += (size_t)nw;
        i++;
    }
    if (fclose(fp) != 0)
        return -1;
    return 0;
}

static int cps_link_target(const char *path, char *out, size_t cap)
{
    ssize_t n = readlink(path, out, cap - 1);
    if (n < 0)
        return -1;
    out[n] = '\0';
    return 0;
}

static int cps_test_usage(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[512];
    char err[512];
    char err2[512];
    int rc;
    const char *usage =
        "c23-portable-sysroot: usage: c23-portable-sysroot "
        "[prepare|cc-path|root-path|verify]\n";
    TEST("unknown mode and a missing repo are refused") {
        ASSERT(cps_case(root, "usage", dir, sizeof dir) == 0);
        rc = cps_capture(dir, dir, "nope", out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(out, "");
        ASSERT_STR_EQ(err, usage);
        rc = cps_capture(dir, dir, "nope", out, sizeof out, err2, sizeof err2);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(err2, err);
        rc = cps_capture(dir, NULL, "prepare", out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(out, "");
        ASSERT_STR_EQ(err, "c23-portable-sysroot: repo is required\n");
        rc = cps_capture(dir, "", "prepare", out, sizeof out, err2, sizeof err2);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(err2, err);
        PASS();
    }
    _test_next:;
    return failures;
}

static int cps_test_tools(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[64];
    char err[256];
    char err2[256];
    char old[8192];
    int rc;
    TEST("a missing required tool is refused before download") {
        ASSERT(cps_case(root, "tools", dir, sizeof dir) == 0);
        ASSERT(cps_bind(dir, NULL, 1, old, sizeof old) == 0);
        if (setenv("PATH", dir, 1) != 0) {
            cps_unbind(old);
            ASSERT(0);
        }
        rc = cps_capture(dir, dir, NULL, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(out, "");
        ASSERT_STR_EQ(err, "c23-portable-sysroot: required tool not found: ar\n");
        rc = cps_capture(dir, dir, "", out, sizeof out, err2, sizeof err2);
        cps_unbind(old);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(err2, err);
        PASS();
    }
    _test_next:;
    cps_unbind(old);
    return failures;
}

static int cps_test_prepare(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[PATH_MAX];
    char again[PATH_MAX];
    char root_out[PATH_MAX];
    char err[1024];
    char wrap[8192];
    char cc[PATH_MAX];
    char sys[PATH_MAX];
    char path[PATH_MAX];
    char wrapper[PATH_MAX];
    int rc;
    TEST("prepare and root-path publish the quoted baseline wrapper") {
        ASSERT(cps_case(root, "prep", dir, sizeof dir) == 0);
        ASSERT(cps_plant_fresh(dir) == 0);
        ASSERT(cps_cc_path(dir, cc, sizeof cc) == 0);
        ASSERT(cps_sysroot(dir, sys, sizeof sys) == 0);
        rc = cps_drive(dir, cc, "prepare", 0, out, sizeof out, err, sizeof err);
        test_note("rc=%d err=%s", rc, err);
        ASSERT_EQ(rc, 0);
        ASSERT(cps_rel(dir, "build/toolchains/debian-bullseye-glibc-2.31-amd64/cc", wrapper,
                       sizeof wrapper) == 0);
        ASSERT(snprintf(path, sizeof path, "%s\n", wrapper) > 0);
        ASSERT_STR_EQ(out, path);
        ASSERT_STR_EQ(err, "");
        rc = cps_drive(dir, cc, "cc-path", 0, again, sizeof again, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT_STR_EQ(again, out);
        rc = cps_drive(dir, cc, "root-path", 0, root_out, sizeof root_out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT(snprintf(path, sizeof path, "%s\n", sys) > 0);
        ASSERT_STR_EQ(root_out, path);
        ASSERT(cps_read(wrapper, wrap, sizeof wrap) == 0);
        ASSERT(strstr(wrap, "#!/bin/sh\n") == wrap);
        ASSERT(strstr(wrap, "-march=x86-64") != NULL);
        ASSERT(strstr(wrap, "-mtune=generic") != NULL);
        ASSERT(strstr(wrap, "\"$@\"") != NULL);
        ASSERT(strstr(wrap, "--sysroot=") != NULL);
        ASSERT(strstr(wrap, sys) != NULL);
        ASSERT(strstr(wrap, "/bin/cc\\ tool") != NULL);
        ASSERT(strchr(wrap, '\'') == NULL);
        ASSERT(strstr(wrap, "/usr/lib/x86_64-linux-gnu/") != NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int cps_test_compiler(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[64];
    char err[PATH_MAX];
    char want[PATH_MAX];
    int rc;
    TEST("a missing C23 compiler is refused after the sysroot is fresh") {
        ASSERT(cps_case(root, "cc", dir, sizeof dir) == 0);
        ASSERT(cps_plant_fresh(dir) == 0);
        rc = cps_drive(dir, "/no/such/c23-cc", "prepare", 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(out, "");
        ASSERT(snprintf(want, sizeof want,
                        "c23-portable-sysroot: C23 compiler not found: /no/such/c23-cc\n") > 0);
        ASSERT_STR_EQ(err, want);
        PASS();
    }
    _test_next:;
    return failures;
}

static int cps_test_verify(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[64];
    char err[PATH_MAX];
    char cc[PATH_MAX];
    char sys[PATH_MAX];
    char want[PATH_MAX];
    char path[PATH_MAX];
    int rc;
    TEST("verify accepts the floor and refuses an ISA leak or a newer ABI") {
        ASSERT(cps_case(root, "verify", dir, sizeof dir) == 0);
        ASSERT(cps_plant_fresh(dir) == 0);
        ASSERT(cps_cc_path(dir, cc, sizeof cc) == 0);
        ASSERT(cps_sysroot(dir, sys, sizeof sys) == 0);
        rc = cps_drive(dir, cc, "verify", 0, out, sizeof out, err, sizeof err);
        test_note("pass rc=%d err=%s", rc, err);
        ASSERT_EQ(rc, 0);
        ASSERT_STR_EQ(out, "");
        ASSERT(snprintf(want, sizeof want,
                        "c23-portable-sysroot: PASS compiler=%s cpu=x86-64 "
                        "max_abi=GLIBC_2.31 sysroot=%s\n",
                        cc, sys) > 0);
        ASSERT_STR_EQ(err, want);
        ASSERT(cps_plant_macros(dir, 20000) == 0);
        rc = cps_drive(dir, cc, "verify", 0, out, sizeof out, err, sizeof err);
        test_note("wide rc=%d err=%s", rc, err);
        ASSERT_EQ(rc, 0);
        ASSERT_STR_EQ(err, want);
        ASSERT(cps_rel(dir, "macros", path, sizeof path) == 0);
        ASSERT(cps_put(path, "#define __AVX2__ 1\n") == 0);
        rc = cps_drive(dir, cc, "verify", 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(err, "leaked a post-x86-64-baseline ISA") != NULL);
        unlink(path);
        ASSERT(cps_rel(dir, "objdump.out", path, sizeof path) == 0);
        ASSERT(cps_put(path, "GLIBC_2.4\nGLIBC_2.34\n") == 0);
        rc = cps_drive(dir, cc, "verify", 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(err, "raised the ABI above GLIBC_2.31: GLIBC_2.34") != NULL);
        unlink(path);
        ASSERT(cps_rel(dir, "cc.fail", path, sizeof path) == 0);
        ASSERT(cps_put(path, "x\n") == 0);
        rc = cps_drive(dir, cc, "verify", 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 7);
        ASSERT(strstr(err, "PASS") == NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int cps_test_fetch(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[64];
    char err[2048];
    char path[PATH_MAX];
    int rc;
    TEST("fetch refuses a bad checksum and a missing downloader") {
        ASSERT(cps_case(root, "fetch", dir, sizeof dir) == 0);
        ASSERT(cps_link(dir, "curl") == 0);
        ASSERT(cps_rel(dir, "sha.fail", path, sizeof path) == 0);
        ASSERT(cps_put(path, "x\n") == 0);
        rc = cps_drive(dir, NULL, "prepare", 0, out, sizeof out, err, sizeof err);
        test_note("checksum rc=%d err=%s", rc, err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(err, "c23-portable-sysroot: fetch https://snapshot.debian.org/") != NULL);
        ASSERT(snprintf(path, sizeof path, "checksum mismatch for %s", k_deb) > 0);
        ASSERT(strstr(err, path) != NULL);
        ASSERT(cps_case(root, "wget", dir, sizeof dir) == 0);
        ASSERT(cps_link(dir, "xz") == 0);
        ASSERT(cps_link(dir, "mktemp") == 0);
        rc = cps_drive(dir, NULL, "prepare", 1, out, sizeof out, err, sizeof err);
        test_note("wget rc=%d err=%s", rc, err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(err, "required tool not found: wget") != NULL);
        ASSERT(strstr(err, "c23-portable-sysroot: fetch ") != NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int cps_test_stage(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[PATH_MAX];
    char err[1024];
    char cc[PATH_MAX];
    char path[PATH_MAX];
    char target[PATH_MAX];
    char stamp[128];
    struct stat st;
    int rc;
    TEST("extract rewrites absolute loader and library links") {
        ASSERT(cps_case(root, "stage", dir, sizeof dir) == 0);
        ASSERT(cps_plant_debs(dir) == 0);
        ASSERT(cps_cc_path(dir, cc, sizeof cc) == 0);
        rc = cps_drive(dir, cc, "prepare", 0, out, sizeof out, err, sizeof err);
        test_note("stage rc=%d err=%s out=%s", rc, err, out);
        ASSERT_EQ(rc, 0);
        ASSERT(cps_rel(dir, "build/toolchains/debian-bullseye-glibc-2.31-amd64/root/lib64/ld-linux-x86-64.so.2",
                       path, sizeof path) == 0);
        ASSERT(cps_link_target(path, target, sizeof target) == 0);
        ASSERT_STR_EQ(target, "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2");
        ASSERT(cps_rel(dir,
                       "build/toolchains/debian-bullseye-glibc-2.31-amd64/root/usr/lib/x86_64-linux-gnu/libfoo.so",
                       path, sizeof path) == 0);
        ASSERT(cps_link_target(path, target, sizeof target) == 0);
        ASSERT_STR_EQ(target, "../../../lib/x86_64-linux-gnu/libfoo.so.1");
        ASSERT(cps_rel(dir,
                       "build/toolchains/debian-bullseye-glibc-2.31-amd64/root/usr/lib/x86_64-linux-gnu/libkeep.so",
                       path, sizeof path) == 0);
        ASSERT(cps_link_target(path, target, sizeof target) == 0);
        ASSERT_STR_EQ(target, "libfoo.so.1");
        ASSERT(cps_rel(dir,
                       "build/toolchains/debian-bullseye-glibc-2.31-amd64/root/usr/lib/x86_64-linux-gnu/notlink.so",
                       path, sizeof path) == 0);
        ASSERT(lstat(path, &st) == 0);
        ASSERT(!S_ISLNK(st.st_mode));
        ASSERT(cps_rel(dir, "build/toolchains/debian-bullseye-glibc-2.31-amd64/inputs.sha256", path,
                       sizeof path) == 0);
        ASSERT(cps_read(path, stamp, sizeof stamp) == 0);
        ASSERT(snprintf(path, sizeof path, "%s\n", k_hash) > 0);
        ASSERT_STR_EQ(stamp, path);
        PASS();
    }
    _test_next:;
    return failures;
}

int test_c23_portable_sysroot(void);
int test_c23_portable_sysroot(void)
{
    char root[PATH_MAX];
    int failures = 0;
    test_make_tmpdir(root, sizeof root, "c23_portable_sysroot", "root");
    failures += cps_test_usage(root);
    failures += cps_test_tools(root);
    failures += cps_test_prepare(root);
    failures += cps_test_compiler(root);
    failures += cps_test_verify(root);
    failures += cps_test_fetch(root);
    failures += cps_test_stage(root);
    if (failures == 0)
        printf("test_c23_portable_sysroot: all passed\n");
    else
        printf("test_c23_portable_sysroot: %d FAILED\n", failures);
    return failures;
}
