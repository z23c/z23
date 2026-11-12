/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_simnet_replay_capsule against fixture capsule names and a
 * stand-in wire_sweep that records its arguments. */

#include "test/test_core.h"

#include "simnet_replay_capsule.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int src_capture(int argc, char **argv, const char *log, char *got, size_t cap, int *rc)
{
    int fd = open(log, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    FILE *file;
    size_t used;
    if (fd < 0 || saved_out < 0 || saved_err < 0)
        goto fail;
    fflush(stdout);
    fflush(stderr);
    if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0)
        goto fail;
    *rc = zcl_simnet_replay_capsule(argc, argv);
    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
    close(fd);
    file = fopen(log, "r");
    if (file == NULL)
        return -1;
    used = fread(got, 1, cap - 1, file);
    fclose(file);
    if (used == cap - 1)
        return -1;
    got[used] = '\0';
    return 0;
fail:
    if (saved_out >= 0) {
        dup2(saved_out, STDOUT_FILENO);
        close(saved_out);
    }
    if (saved_err >= 0) {
        dup2(saved_err, STDERR_FILENO);
        close(saved_err);
    }
    if (fd >= 0)
        close(fd);
    return -1;
}

static int src_write(const char *path, const char *text)
{
    FILE *file = fopen(path, "w");
    if (file == NULL)
        return -1;
    if (fputs(text, file) < 0) {
        fclose(file);
        return -1;
    }
    return fclose(file) == 0 ? 0 : -1;
}

static int test_simnet_replay_usage(const char *dir)
{
    int failures = 0;
    TEST("simnet replay: usage, a missing binary, and a missing path are refused") {
        char log[1024];
        char absent[1024];
        char bin[1024];
        char got[2048];
        char *argv_usage[] = {"simnet-replay-capsule", NULL};
        char *argv_bin[] = {"simnet-replay-capsule", "caps", "no-such-wire-sweep", NULL};
        char *argv_path[] = {"simnet-replay-capsule", absent, bin, NULL};
        int rc = 0;
        ASSERT(snprintf(log, sizeof log, "%s/usage.log", dir) > 0);
        ASSERT(snprintf(absent, sizeof absent, "%s/absent.tape", dir) > 0);
        ASSERT(snprintf(bin, sizeof bin, "%s/stand-in", dir) > 0);
        ASSERT(src_capture(1, argv_usage, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 2);
        ASSERT(strstr(got, "usage: simnet-replay-capsule <capsule-dir-or-.tape-file>") != NULL);
        ASSERT(src_capture(3, argv_bin, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 2);
        ASSERT(strstr(got, "wire_sweep binary not found or not executable: no-such-wire-sweep") != NULL);
        ASSERT(src_write(bin, "#!/bin/sh\nexit 0\n") == 0);
        ASSERT(chmod(bin, 0700) == 0);
        ASSERT(src_capture(3, argv_path, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 2);
        ASSERT(strstr(got, "no such capsule path:") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_simnet_replay_dir(const char *dir)
{
    int failures = 0;
    TEST("simnet replay: a directory replays sorted seeds and skips a bad name") {
        char caps[1024];
        char art[1024];
        char bin[1024];
        char log[1024];
        char args[1024];
        char got[4096];
        char args_got[2048];
        char nested[1200];
        char *argv[] = {"simnet-replay-capsule", caps, bin, art, NULL};
        FILE *file;
        int rc = 0;
        ASSERT(snprintf(caps, sizeof caps, "%s/caps", dir) > 0);
        ASSERT(snprintf(art, sizeof art, "%s/out/replay", dir) > 0);
        ASSERT(snprintf(bin, sizeof bin, "%s/wire_sweep", dir) > 0);
        ASSERT(snprintf(log, sizeof log, "%s/dir.log", dir) > 0);
        ASSERT(snprintf(args, sizeof args, "%s/args.log", dir) > 0);
        ASSERT(snprintf(nested, sizeof nested, "%s/caps/nested", dir) > 0);
        ASSERT(mkdir(caps, 0700) == 0);
        ASSERT(mkdir(nested, 0700) == 0);
        ASSERT(src_write(bin,
                         "#!/bin/sh\n"
                         "printf '%s\\n' \"$@\" >> \"$REPLAY_ARGS\"\n"
                         "exit 0\n") == 0);
        ASSERT(chmod(bin, 0700) == 0);
        ASSERT(setenv("REPLAY_ARGS", args, 1) == 0);
        {
            char path[1200];
            ASSERT(snprintf(path, sizeof path, "%s/seed_0x10.tape", caps) > 0);
            ASSERT(src_write(path, "ten\n") == 0);
            ASSERT(snprintf(path, sizeof path, "%s/seed_0x0a.tape", caps) > 0);
            ASSERT(src_write(path, "ten\n") == 0);
            ASSERT(snprintf(path, sizeof path, "%s/seed_0xZZ.tape", caps) > 0);
            ASSERT(src_write(path, "bad\n") == 0);
            ASSERT(snprintf(path, sizeof path, "%s/seed_0x99.tape", nested) > 0);
            ASSERT(src_write(path, "nested\n") == 0);
            ASSERT(snprintf(path, sizeof path, "%s/seed_0xab.tape", caps) > 0);
            ASSERT(symlink("missing-target", path) == 0);
        }
        ASSERT(src_capture(4, argv, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(strstr(got, "==> replaying capsule ") != NULL);
        ASSERT(strstr(got, "(seed=0x0a)") != NULL);
        ASSERT(strstr(got, "(seed=0x10)") != NULL);
        ASSERT(strstr(got, "skipping ") != NULL);
        ASSERT(strstr(got, "seed_0xZZ.tape") != NULL);
        ASSERT(strstr(got, "simnet_replay_capsule: 2/2 replayed seed(s) PASS\n") != NULL);
        ASSERT(strstr(got, "0x99") == NULL);
        ASSERT(strstr(got, "0xab") == NULL);
        file = fopen(args, "r");
        ASSERT(file != NULL);
        ASSERT(fgets(args_got, sizeof args_got, file) != NULL);
        ASSERT(strcmp(args_got, "--start=0x0a\n") == 0);
        ASSERT(fgets(args_got, sizeof args_got, file) != NULL);
        ASSERT(strcmp(args_got, "--count=1\n") == 0);
        ASSERT(fgets(args_got, sizeof args_got, file) != NULL);
        ASSERT(strcmp(args_got, "--verbose\n") == 0);
        ASSERT(fgets(args_got, sizeof args_got, file) != NULL);
        ASSERT(strncmp(args_got, "--artifact-dir=", 15) == 0);
        ASSERT(strstr(args_got, "/out/replay\n") != NULL);
        ASSERT(fgets(args_got, sizeof args_got, file) != NULL);
        ASSERT(strcmp(args_got, "--start=0x10\n") == 0);
        fclose(file);
        ASSERT(access(art, F_OK) == 0);
        PASS();
    } _test_next:;
    unsetenv("REPLAY_ARGS");
    return failures;
}

static int test_simnet_replay_fail(const char *dir)
{
    int failures = 0;
    TEST("simnet replay: one failing seed fails the report and an empty dir does not") {
        char caps[1024];
        char empty[1024];
        char art[1024];
        char untouched[1024];
        char bin[1024];
        char log[1024];
        char got[4096];
        char path[1200];
        char *argv[] = {"simnet-replay-capsule", caps, bin, art, NULL};
        char *empty_argv[] = {"simnet-replay-capsule", empty, bin, untouched, NULL};
        int rc = 0;
        ASSERT(snprintf(caps, sizeof caps, "%s/failcaps", dir) > 0);
        ASSERT(snprintf(empty, sizeof empty, "%s/empty", dir) > 0);
        ASSERT(snprintf(art, sizeof art, "%s/fail-out", dir) > 0);
        ASSERT(snprintf(untouched, sizeof untouched, "%s/should-not-exist", dir) > 0);
        ASSERT(snprintf(bin, sizeof bin, "%s/wire_fail", dir) > 0);
        ASSERT(snprintf(log, sizeof log, "%s/fail.log", dir) > 0);
        ASSERT(mkdir(caps, 0700) == 0);
        ASSERT(mkdir(empty, 0700) == 0);
        ASSERT(src_write(bin, "#!/bin/sh\nexit 1\n") == 0);
        ASSERT(chmod(bin, 0700) == 0);
        ASSERT(snprintf(path, sizeof path, "%s/seed_0x2.tape", caps) > 0);
        ASSERT(src_write(path, "two\n") == 0);
        ASSERT(src_capture(4, argv, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(strstr(got, "(seed=0x2)") != NULL);
        ASSERT(strstr(got, "simnet_replay_capsule: 1/1 replayed seed(s) still FAIL\n") != NULL);
        ASSERT(src_capture(4, empty_argv, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(strstr(got, "no seed_0x*.tape capsule files found under ") != NULL);
        ASSERT(strstr(got, "default directory build/wire-sweep-output/") != NULL);
        ASSERT(access(untouched, F_OK) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_simnet_replay_file(const char *dir)
{
    int failures = 0;
    TEST("simnet replay: one tape file replays, and a fifo is not a capsule") {
        char tape[1024];
        char bad[1024];
        char art[1024];
        char bin[1024];
        char log[1024];
        char args[1024];
        char got[4096];
        char args_got[1200];
        char fifo[1024];
        char *argv[] = {"simnet-replay-capsule", tape, bin, art, NULL};
        char *bad_argv[] = {"simnet-replay-capsule", bad, bin, art, NULL};
        char *fifo_argv[] = {"simnet-replay-capsule", fifo, bin, art, NULL};
        FILE *file;
        int rc = 0;
        ASSERT(snprintf(tape, sizeof tape, "%s/seed_0x2a.tape", dir) > 0);
        ASSERT(snprintf(bad, sizeof bad, "%s/notes.txt", dir) > 0);
        ASSERT(snprintf(art, sizeof art, "%s/file-out", dir) > 0);
        ASSERT(snprintf(bin, sizeof bin, "%s/wire_file", dir) > 0);
        ASSERT(snprintf(log, sizeof log, "%s/file.log", dir) > 0);
        ASSERT(snprintf(args, sizeof args, "%s/file-args.log", dir) > 0);
        ASSERT(snprintf(fifo, sizeof fifo, "%s/capsule.fifo", dir) > 0);
        ASSERT(src_write(bin,
                         "#!/bin/sh\n"
                         "printf '%s\\n' \"$@\" >> \"$REPLAY_ARGS\"\n"
                         "exit 0\n") == 0);
        ASSERT(chmod(bin, 0700) == 0);
        ASSERT(setenv("REPLAY_ARGS", args, 1) == 0);
        ASSERT(src_write(tape, "tape\n") == 0);
        ASSERT(src_write(bad, "nope\n") == 0);
        ASSERT(src_capture(4, argv, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(strstr(got, "(seed=0x2a)") != NULL);
        ASSERT(strstr(got, "simnet_replay_capsule: 1/1 replayed seed(s) PASS\n") != NULL);
        file = fopen(args, "r");
        ASSERT(file != NULL);
        ASSERT(fgets(args_got, sizeof args_got, file) != NULL);
        ASSERT(strcmp(args_got, "--start=0x2a\n") == 0);
        ASSERT(fgets(args_got, sizeof args_got, file) != NULL);
        ASSERT(strcmp(args_got, "--count=1\n") == 0);
        ASSERT(fgets(args_got, sizeof args_got, file) != NULL);
        ASSERT(strcmp(args_got, "--verbose\n") == 0);
        ASSERT(fgets(args_got, sizeof args_got, file) != NULL);
        ASSERT(strncmp(args_got, "--artifact-dir=", 15) == 0);
        ASSERT(strstr(args_got, "/file-out\n") != NULL);
        fclose(file);
        ASSERT(src_capture(4, bad_argv, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(strstr(got, "found 1 file(s) but none matched seed_0x<HEX>.tape") != NULL);
        ASSERT(mkfifo(fifo, 0600) == 0);
        ASSERT(src_capture(4, fifo_argv, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 2);
        ASSERT(strstr(got, "is neither a directory nor a file") != NULL);
        PASS();
    } _test_next:;
    unsetenv("REPLAY_ARGS");
    return failures;
}

int test_simnet_replay_capsule(void);
int test_simnet_replay_capsule(void)
{
    char dir[1024];
    int failures;
    test_make_tmpdir(dir, sizeof dir, "simnet_replay", "root");
    failures = test_simnet_replay_usage(dir);
    failures += test_simnet_replay_dir(dir);
    failures += test_simnet_replay_fail(dir);
    failures += test_simnet_replay_file(dir);
    (void)test_rm_rf_recursive(dir);
    if (failures == 0)
        printf("test_simnet_replay_capsule: all passed\n");
    else
        printf("test_simnet_replay_capsule: %d FAILED\n", failures);
    return failures;
}
