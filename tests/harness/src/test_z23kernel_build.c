/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_z23kernel_build on apps/z23kernel with the checked LLVM tools.
 * The published image must match the identity line's SHA-256. */

#include "test/test_core.h"

#include "z23kernel_build.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int zk_fit(int n, int cap)
{
    return n > 0 && n < cap;
}

static int zk_spawn_text(char *const argv[], char *out, size_t cap)
{
    int fds[2];
    pid_t pid;
    ssize_t n;
    if (pipe(fds) != 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0)
            _exit(127);
        close(fds[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(fds[1]);
    n = read(fds[0], out, cap - 1);
    close(fds[0]);
    if (n < 0)
        n = 0;
    out[n] = '\0';
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
        ;
    return 0;
}

static int zk_tool_dir(const char *root)
{
    char path[768];
    int n = snprintf(path, sizeof path, "%s/bin/ld.lld", root);
    if (n < 0 || n >= (int)sizeof path || access(path, X_OK) != 0)
        return 0;
    n = snprintf(path, sizeof path, "%s/bin/clang", root);
    return n > 0 && n < (int)sizeof path && access(path, X_OK) == 0;
}

static int zk_llvm_bin(char *dir, size_t cap)
{
    struct passwd *pw = getpwuid(getuid());
    char root[512];
    DIR *scan;
    struct dirent *ent;
    int n;
    if (pw == NULL || pw->pw_dir == NULL || pw->pw_dir[0] == '\0')
        return -1;
    n = snprintf(root, sizeof root, "%s/.cache/z23/toolchain", pw->pw_dir);
    if (n < 0 || n >= (int)sizeof root)
        return -1;
    scan = opendir(root);
    if (scan == NULL)
        return -1;
    while ((ent = readdir(scan)) != NULL) {
        char cand[768];
        if (ent->d_name[0] == '.')
            continue;
        n = snprintf(cand, sizeof cand, "%s/%s", root, ent->d_name);
        if (n < 0 || n >= (int)sizeof cand || !zk_tool_dir(cand))
            continue;
        closedir(scan);
        return snprintf(dir, cap, "%s/bin", cand) < (int)cap ? 0 : -1;
    }
    closedir(scan);
    return -1;
}

static int zk_sha256(const char *path, char hex[65])
{
    char line[256];
    char *argv[] = {"sha256sum", (char *)path, NULL};
    char *field;
    if (zk_spawn_text(argv, line, sizeof line) != 0)
        return -1;
    field = line;
    while (*field == ' ' || *field == '\t')
        field++;
    if (strlen(field) < 64)
        return -1;
    memcpy(hex, field, 64);
    hex[64] = '\0';
    return field[64] == ' ' || field[64] == '\t' ? 0 : -1;
}

#if defined(__APPLE__)
static int zk_tool_join(char *out, size_t cap, const char *bin, const char *name)
{
    int n = snprintf(out, cap, "%s/%s", bin, name);
    return zk_fit(n, (int)cap) ? 0 : -1;
}

static long zk_marker_bytes(const char *marker)
{
    FILE *fp = fopen(marker, "rb");
    long n = 0;
    int c;
    if (fp == NULL)
        return 0;
    c = fgetc(fp);
    while (c != EOF) {
        if (c != 'x') {
            fclose(fp);
            return -1;
        }
        n++;
        c = fgetc(fp);
    }
    if (fclose(fp) != 0)
        return -1;
    return n;
}

static int zk_write_shim(const char *path)
{
    FILE *fp = fopen(path, "w");
    const char *body =
        "#!/bin/sh\n"
        "printf x >> \"$ZCL_KERNEL_SPAWN\"\n"
        "PATH=${PATH#*:}\n"
        "export PATH\n"
        "exec sha256sum \"$@\"\n";
    if (fp == NULL)
        return -1;
    if (fputs(body, fp) < 0) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0)
        return -1;
    return chmod(path, 0755) == 0 ? 0 : -1;
}

static int zk_arm_path(const char *dir, char *saved, size_t cap)
{
    char shim[1200];
    char marker[1200];
    char path_env[9000];
    const char *cur = getenv("PATH");
    int n;
    if (cur == NULL || strlen(cur) + 1 > cap)
        return -1;
    memcpy(saved, cur, strlen(cur) + 1);
    n = snprintf(shim, sizeof shim, "%s/sha256sum", dir);
    if (!zk_fit(n, (int)sizeof shim) || zk_write_shim(shim) != 0)
        return -1;
    n = snprintf(marker, sizeof marker, "%s/spawn", dir);
    if (!zk_fit(n, (int)sizeof marker))
        return -1;
    n = snprintf(path_env, sizeof path_env, "%s:%s", dir, saved);
    if (!zk_fit(n, (int)sizeof path_env))
        return -1;
    if (setenv("ZCL_KERNEL_SPAWN", marker, 1) != 0)
        return -1;
    return setenv("PATH", path_env, 1);
}

static int zk_hash_build(const char *dir, const char *llvm)
{
    char cc[640], ld[640], objcopy[640], readelf[640], nm[640];
    char out[1024], bin[1024];
    int n;
    if (zk_tool_join(cc, sizeof cc, llvm, "clang") != 0 ||
        zk_tool_join(ld, sizeof ld, llvm, "ld.lld") != 0 ||
        zk_tool_join(objcopy, sizeof objcopy, llvm, "llvm-objcopy") != 0 ||
        zk_tool_join(readelf, sizeof readelf, llvm, "llvm-readelf") != 0 ||
        zk_tool_join(nm, sizeof nm, llvm, "llvm-nm") != 0)
        return -1;
    n = snprintf(out, sizeof out, "%s/hout", dir);
    if (!zk_fit(n, (int)sizeof out))
        return -1;
    n = snprintf(bin, sizeof bin, "%s/hbin", dir);
    if (!zk_fit(n, (int)sizeof bin))
        return -1;
    if (mkdir(out, 0700) != 0 || mkdir(bin, 0700) != 0)
        return -1;
    return zcl_z23kernel_build("apps/z23kernel", out, bin, cc, ld, objcopy,
                               readelf, nm);
}

static int zk_identity_matches(const char *dir, int *digest_ok)
{
    char image[1200];
    char identity[1200];
    char hash[65];
    char got[128];
    FILE *file;
    int n;
    *digest_ok = 0;
    n = snprintf(image, sizeof image, "%s/hbin/z23kernel.bin", dir);
    if (!zk_fit(n, (int)sizeof image))
        return -1;
    n = snprintf(identity, sizeof identity, "%s/hbin/z23kernel.identity", dir);
    if (!zk_fit(n, (int)sizeof identity))
        return -1;
    if (zk_sha256(image, hash) != 0)
        return -1;
    file = fopen(identity, "r");
    if (file == NULL)
        return -1;
    if (fgets(got, (int)sizeof got, file) == NULL) {
        fclose(file);
        return -1;
    }
    fclose(file);
    *digest_ok = strncmp(got, hash, 64) == 0 && got[64] == ' ';
    return 0;
}

/* The published identity must be SHA-256 of the image, with no sha256sum. */
static int zk_hash_spawn(const char *dir)
{
    char llvm[512];
    char saved[8192];
    char marker[1200];
    long spawn = -1;
    int digest_ok = 0;
    int rc = 1;
    int n;
    if (zk_llvm_bin(llvm, sizeof llvm) == 0 &&
        zk_arm_path(dir, saved, sizeof saved) == 0) {
        rc = zk_hash_build(dir, llvm);
        if (setenv("PATH", saved, 1) != 0)
            rc = 1;
        unsetenv("ZCL_KERNEL_SPAWN");
        n = snprintf(marker, sizeof marker, "%s/spawn", dir);
        if (zk_fit(n, (int)sizeof marker))
            spawn = zk_marker_bytes(marker);
        if (rc == 0 && zk_identity_matches(dir, &digest_ok) != 0)
            digest_ok = 0;
    }
    printf("kernel_hash: status=%d spawn=%ld digest_ok=%d\n", rc, spawn,
           digest_ok);
    fflush(stdout);
    if (rc != 0 || digest_ok == 0 || spawn != 0)
        return 1;
    return 0;
}
#else
static int zk_hash_spawn(const char *dir)
{
    (void)dir;
    printf("kernel_hash: skip\n");
    return 0;
}
#endif

static int test_z23kernel_build_cases(const char *dir)
{
    int failures = 0;
    TEST("z23kernel build: real image identity and a missing source") {
        char llvm[512];
        char cc[640], ld[640], objcopy[640], readelf[640], nm[640];
        char out[1024], bin[1024], image[1200], identity[1200];
        char got[128], hash[65];
        struct stat st;
        FILE *file;
        int n;
        int rc;
        ASSERT(zk_llvm_bin(llvm, sizeof llvm) == 0);
        n = snprintf(cc, sizeof cc, "%s/clang", llvm);
        ASSERT(zk_fit(n, (int)sizeof cc));
        n = snprintf(ld, sizeof ld, "%s/ld.lld", llvm);
        ASSERT(zk_fit(n, (int)sizeof ld));
        n = snprintf(objcopy, sizeof objcopy, "%s/llvm-objcopy", llvm);
        ASSERT(zk_fit(n, (int)sizeof objcopy));
        n = snprintf(readelf, sizeof readelf, "%s/llvm-readelf", llvm);
        ASSERT(zk_fit(n, (int)sizeof readelf));
        n = snprintf(nm, sizeof nm, "%s/llvm-nm", llvm);
        ASSERT(zk_fit(n, (int)sizeof nm));
        n = snprintf(out, sizeof out, "%s/out", dir);
        ASSERT(zk_fit(n, (int)sizeof out));
        n = snprintf(bin, sizeof bin, "%s/bin", dir);
        ASSERT(zk_fit(n, (int)sizeof bin));
        ASSERT(mkdir(out, 0700) == 0);
        ASSERT(mkdir(bin, 0700) == 0);
        rc = zcl_z23kernel_build("apps/z23kernel", out, bin, cc, ld, objcopy,
                                 readelf, nm);
        ASSERT(rc == 0);
        n = snprintf(image, sizeof image, "%s/z23kernel.bin", bin);
        ASSERT(zk_fit(n, (int)sizeof image));
        n = snprintf(identity, sizeof identity, "%s/z23kernel.identity", bin);
        ASSERT(zk_fit(n, (int)sizeof identity));
        ASSERT(stat(image, &st) == 0);
        ASSERT(S_ISREG(st.st_mode));
        ASSERT(st.st_size > 0);
        ASSERT(st.st_size < 65536);
        ASSERT(zk_sha256(image, hash) == 0);
        file = fopen(identity, "r");
        ASSERT(file != NULL);
        ASSERT(fgets(got, (int)sizeof got, file) != NULL);
        fclose(file);
        ASSERT(strncmp(got, hash, 64) == 0);
        ASSERT(got[64] == ' ');
        rc = zcl_z23kernel_build("/no/such/z23kernel-source", out, bin, cc, ld,
                                 objcopy, readelf, nm);
        ASSERT(rc != 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_z23kernel_build(void);
int test_z23kernel_build(void)
{
    char dir[1024];
    int failures;
    test_make_tmpdir(dir, sizeof dir, "z23kernel_build", "root");
    failures = test_z23kernel_build_cases(dir);
    failures += zk_hash_spawn(dir);
    (void)test_rm_rf_recursive(dir);
    if (failures == 0)
        printf("test_z23kernel_build: all passed\n");
    else
        printf("test_z23kernel_build: %d FAILED\n", failures);
    return failures;
}
