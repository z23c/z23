/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Replay wire_sweep from seed_0x<HEX>.tape filenames. The tape
 *          bytes are not read; the seed is the filename. */

#include "simnet_replay_capsule.h"

#include <stdio.h>

#if !defined(_WIN32)
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int sr_hex(char c)
{
    if (c >= '0' && c <= '9')
        return 1;
    if (c >= 'a' && c <= 'f')
        return 1;
    if (c >= 'A' && c <= 'F')
        return 1;
    return 0;
}

static int sr_seed(const char *base, char *hex, size_t cap)
{
    size_t n = 0;
    if (strncmp(base, "seed_0x", 7) != 0)
        return -1;
    while (sr_hex(base[7 + n]))
        n++;
    if (n < 1 || n > 16)
        return -1;
    if (strcmp(base + 7 + n, ".tape") != 0)
        return -1;
    if (n + 3 > cap)
        return -1;
    memcpy(hex, base + 5, n + 2);
    hex[n + 2] = '\0';
    return 0;
}

static int sr_keep(const struct dirent *de)
{
    const char *name = de->d_name;
    size_t n = strlen(name);
    if (strncmp(name, "seed_0x", 7) != 0)
        return 0;
    if (n < 12 || strcmp(name + n - 5, ".tape") != 0)
        return 0;
    return 1;
}

static int sr_cmp(const struct dirent **a, const struct dirent **b)
{
    return strcmp((*a)->d_name, (*b)->d_name);
}

static int sr_join(char *dst, size_t cap, const char *dir, const char *name)
{
    size_t n = strlen(dir);
    int wrote;
    if (n > 0 && dir[n - 1] == '/')
        wrote = snprintf(dst, cap, "%s%s", dir, name);
    else
        wrote = snprintf(dst, cap, "%s/%s", dir, name);
    if (wrote < 0 || (size_t)wrote >= cap)
        return -1;
    return 0;
}

static int sr_reg(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return 0;
    return S_ISREG(st.st_mode);
}

static int sr_mkdir_p(char *path)
{
    char *p;
    if (path[0] == '\0')
        return -1;
    for (p = path + 1; *p != '\0'; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(path, 0777) != 0 && errno != EEXIST) {
            *p = '/';
            return -1;
        }
        *p = '/';
    }
    if (mkdir(path, 0777) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int sr_run(const char *bin, const char *seed, const char *art)
{
    char start[80];
    char dest[PATH_MAX];
    char *argv[6];
    pid_t pid;
    int status = 1;
    if (snprintf(start, sizeof start, "--start=%s", seed) >= (int)sizeof start)
        return 1;
    if (snprintf(dest, sizeof dest, "--artifact-dir=%s", art) >= (int)sizeof dest)
        return 1;
    argv[0] = (char *)bin;
    argv[1] = start;
    argv[2] = "--count=1";
    argv[3] = "--verbose";
    argv[4] = dest;
    argv[5] = NULL;
    pid = fork();
    if (pid < 0)
        return 1;
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    for (;;) {
        pid_t got = waitpid(pid, &status, 0);
        if (got == pid)
            break;
        if (errno != EINTR)
            return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 1;
    return 0;
}

static void sr_one(const char *path, const char *bin, const char *art,
                   int *failures, int *replayed)
{
    const char *slash = strrchr(path, '/');
    const char *name = slash != NULL ? slash + 1 : path;
    char seed[24];
    if (sr_seed(name, seed, sizeof seed) != 0) {
        fprintf(stderr,
                "simnet_replay_capsule: skipping %s (name does not match seed_0x<HEX>.tape)\n",
                path);
        return;
    }
    *replayed += 1;
    printf("==> replaying capsule %s (seed=%s)\n", path, seed);
    if (sr_run(bin, seed, art) != 0)
        *failures += 1;
}

static int sr_finish(int found, int replayed, int failures)
{
    if (replayed == 0) {
        fprintf(stderr,
                "simnet_replay_capsule: found %d file(s) but none matched seed_0x<HEX>.tape\n",
                found);
        return 1;
    }
    if (failures != 0) {
        printf("simnet_replay_capsule: %d/%d replayed seed(s) still FAIL\n",
               failures, replayed);
        return 1;
    }
    printf("simnet_replay_capsule: %d/%d replayed seed(s) PASS\n",
           replayed, replayed);
    return 0;
}

static int sr_none(const char *cap)
{
    fprintf(stderr,
            "simnet_replay_capsule: no seed_0x*.tape capsule files found under %s\n",
            cap);
    fprintf(stderr,
            "  (capsules are written by 'make wire-sweep' on a monitor failure,\n");
    fprintf(stderr, "   default directory build/wire-sweep-output/)\n");
    return 1;
}

static void sr_free(struct dirent **names, int n)
{
    int i;
    for (i = 0; i < n; i++)
        free(names[i]);
    free(names);
}

static int sr_prepare(const char *art)
{
    char owned[PATH_MAX];
    int n = snprintf(owned, sizeof owned, "%s", art);
    if (n < 0 || (size_t)n >= sizeof owned)
        return 2;
    if (sr_mkdir_p(owned) != 0)
        return 1;
    return 0;
}

static int sr_file(const char *path, const char *bin, const char *art)
{
    int failures = 0;
    int replayed = 0;
    int ready = sr_prepare(art);
    if (ready != 0)
        return ready;
    sr_one(path, bin, art, &failures, &replayed);
    return sr_finish(1, replayed, failures);
}

static int sr_dir(const char *cap, const char *bin, const char *art)
{
    struct dirent **names = NULL;
    int n = scandir(cap, &names, sr_keep, sr_cmp);
    int i;
    int found = 0;
    int failures = 0;
    int replayed = 0;
    int ready;
    if (n < 0)
        return sr_none(cap);
    if (n == 0) {
        free(names);
        return sr_none(cap);
    }
    for (i = 0; i < n; i++) {
        char path[PATH_MAX];
        if (sr_join(path, sizeof path, cap, names[i]->d_name) != 0)
            continue;
        if (sr_reg(path))
            found++;
    }
    if (found == 0) {
        sr_free(names, n);
        return sr_none(cap);
    }
    ready = sr_prepare(art);
    if (ready != 0) {
        sr_free(names, n);
        return ready;
    }
    for (i = 0; i < n; i++) {
        char path[PATH_MAX];
        if (sr_join(path, sizeof path, cap, names[i]->d_name) != 0)
            continue;
        if (!sr_reg(path))
            continue;
        sr_one(path, bin, art, &failures, &replayed);
    }
    sr_free(names, n);
    return sr_finish(found, replayed, failures);
}

static int sr_go(const char *cap, const char *bin, const char *art)
{
    struct stat st;
    if (bin == NULL || access(bin, X_OK) != 0) {
        fprintf(stderr,
                "simnet_replay_capsule: wire_sweep binary not found or not executable: %s\n",
                bin != NULL ? bin : "");
        return 2;
    }
    if (cap == NULL || stat(cap, &st) != 0) {
        fprintf(stderr, "simnet_replay_capsule: no such capsule path: %s\n",
                cap != NULL ? cap : "");
        return 2;
    }
    if (S_ISDIR(st.st_mode))
        return sr_dir(cap, bin, art);
    if (S_ISREG(st.st_mode))
        return sr_file(cap, bin, art);
    fprintf(stderr, "simnet_replay_capsule: %s is neither a directory nor a file\n",
            cap);
    return 2;
}
#endif

int zcl_simnet_replay_capsule(int argc, char **argv)
{
#if defined(_WIN32)
    const char *name = "simnet_replay_capsule";
    (void)argc;
    (void)argv;
    fprintf(stderr, "usage: %s <capsule-dir-or-.tape-file> <wire_sweep-bin> [artifact-dir]\n",
            name);
    return 2;
#else
    const char *name = "simnet_replay_capsule";
    const char *art = "build/simnet-repro-output";
    if (argc >= 1 && argv != NULL && argv[0] != NULL && argv[0][0] != '\0')
        name = argv[0];
    if (argc < 3 || argv == NULL || argv[1] == NULL || argv[2] == NULL) {
        fprintf(stderr,
                "usage: %s <capsule-dir-or-.tape-file> <wire_sweep-bin> [artifact-dir]\n",
                name);
        return 2;
    }
    if (argc >= 4 && argv[3] != NULL && argv[3][0] != '\0')
        art = argv[3];
    return sr_go(argv[1], argv[2], art);
#endif
}
