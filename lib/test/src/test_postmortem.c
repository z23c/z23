/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "config/boot.h"
#include "platform/os_sandbox.h"
#include "sim/postmortem.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#include <unistd.h>

#define PM_CHECK(name, expr) do { \
    printf("postmortem: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static bool file_contains(const char *path, const char *needle)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    return strstr(buf, needle) != NULL;
}

static bool write_text_file(const char *path, const char *text)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) return false;
    if (text && fputs(text, fp) < 0) {
        fclose(fp);
        return false;
    }
    return fclose(fp) == 0;
}

static int test_postmortem_install_validates_dir(void)
{
    int failures = 0;
    char dir_template[128];
    snprintf(dir_template, sizeof(dir_template),
             "/tmp/zcl_postmortem_install_%d_XXXXXX", (int)getpid());
    char *dir = mkdtemp(dir_template);
    PM_CHECK("install validation mkdtemp", dir != NULL);
    if (!dir) return failures + 1;

    seed_tape_t *tape = seed_tape_open(0x494e5354414c4cULL, 1779670000);
    PM_CHECK("install validation seed tape open", tape != NULL);
    if (!tape) {
        test_rm_rf_recursive(dir);
        return failures + 1;
    }

    char pm_dir[256];
    snprintf(pm_dir, sizeof(pm_dir), "%s/postmortems-created", dir);
    int rc = postmortem_install(tape, pm_dir);
    struct stat st;
    PM_CHECK("install creates capsule dir",
             rc == 0 && stat(pm_dir, &st) == 0 && S_ISDIR(st.st_mode));
    postmortem_uninstall();

    char not_dir[256];
    snprintf(not_dir, sizeof(not_dir), "%s/not-a-dir", dir);
    FILE *fp = fopen(not_dir, "wb");
    PM_CHECK("install validation creates file", fp != NULL);
    if (fp) {
        fputs("not a directory\n", fp);
        fclose(fp);
    }

    rc = postmortem_install(tape, not_dir);
    PM_CHECK("install rejects non-directory path", rc == -ENOTDIR);

    seed_tape_close(tape);
    test_rm_rf_recursive(dir);
    return failures;
}

static int test_signal_handler_capsule(void)
{
    int failures = 0;
    char dir_template[128];
    snprintf(dir_template, sizeof(dir_template),
             "/tmp/zcl_postmortem_signal_%d_XXXXXX", (int)getpid());
    char *dir = mkdtemp(dir_template);
    PM_CHECK("signal mkdtemp", dir != NULL);
    if (!dir) return failures + 1;

    seed_tape_t *tape = seed_tape_open(0x51616b65ULL, 1779669000);
    PM_CHECK("signal seed tape open", tape != NULL);
    if (tape) {
        seed_tape_advance(tape, 1234);
        seed_tape_inject(tape, 13, "sig", 3);
    }

    pid_t pid = fork();
    if (pid == 0) {
        if (!tape || postmortem_install(tape, dir) != 0)
            _exit(121);
        raise(SIGABRT);
        _exit(122);
    }

    if (pid < 0) {
        PM_CHECK("fork signal child", false);
    } else {
        PM_CHECK("fork signal child", true);
        int status = 0;
        pid_t got = waitpid(pid, &status, 0);
        PM_CHECK("wait signal child", got == pid);
        PM_CHECK("child terminated by SIGABRT",
                 got == pid && WIFSIGNALED(status) &&
                 WTERMSIG(status) == SIGABRT);

        struct postmortem_capsule_entry entries[1];
        size_t count = 0;
        int rc = postmortem_capsule_list(dir, entries, 1, &count);
        PM_CHECK("signal capsule listed", rc == 0 && count == 1);
        PM_CHECK("signal capsule records signal",
                 rc == 0 && count == 1 && entries[0].crash_signal == SIGABRT);
        if (rc == 0 && count == 1) {
            char proc_path[576];
            snprintf(proc_path, sizeof(proc_path), "%s/procstatus.txt",
                     entries[0].path);
#if defined(__linux__)
            PM_CHECK("signal capsule captures proc status",
                     file_contains(proc_path, "Name:"));
#else
            PM_CHECK("signal capsule records proc status limitation",
                      file_contains(proc_path,
                                    OS_SANDBOX_PROC_SELF_STATUS_PATH
                                    " is Linux-only"));
#endif
            char manifest_path[576];
            snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json",
                     entries[0].path);
            PM_CHECK("signal manifest records build id",
                     file_contains(manifest_path, "\"build_id\":"));
            PM_CHECK("signal manifest records clock count",
                     file_contains(manifest_path,
                                   "\"clock_advance_count\": 1"));
            PM_CHECK("signal manifest records inject count",
                     file_contains(manifest_path, "\"inject_count\": 1"));
            char regs_path[576];
            snprintf(regs_path, sizeof(regs_path), "%s/registers.txt",
                     entries[0].path);
            PM_CHECK("signal capsule captures register context",
                     file_contains(regs_path, "signal: 6") &&
                     file_contains(regs_path, "fault_addr:"));
            seed_tape_t *loaded = postmortem_capsule_load_tape(entries[0].path);
            PM_CHECK("signal capsule tape loads", loaded != NULL);
            if (loaded) {
                PM_CHECK("signal capsule preserves event",
                         seed_tape_inject_count(loaded) == 1);
                seed_tape_close(loaded);
            }
        }
    }

    seed_tape_close(tape);
    test_rm_rf_recursive(dir);
    return failures;
}

static int test_boot_postmortem_install(void)
{
    int failures = 0;
    char dir_template[128];
    snprintf(dir_template, sizeof(dir_template),
             "/tmp/zcl_boot_postmortem_%d_XXXXXX", (int)getpid());
    char *dir = mkdtemp(dir_template);
    PM_CHECK("boot postmortem mkdtemp", dir != NULL);
    if (!dir) return failures + 1;

    char log_seed_path[256];
    snprintf(log_seed_path, sizeof(log_seed_path), "%s/node.log", dir);
    PM_CHECK("boot postmortem seed log",
             write_text_file(log_seed_path, "boot fatal breadcrumb\n"));

    bool ok = boot_postmortem_init_for_testing(dir);
    const char *pm_dir = boot_postmortem_dir_for_testing();
    PM_CHECK("boot postmortem init", ok && pm_dir != NULL);

    pid_t pid = fork();
    if (pid == 0) {
        if (!ok || !pm_dir)
            _exit(121);
        raise(SIGABRT);
        _exit(122);
    }

    if (pid < 0) {
        PM_CHECK("boot postmortem fork", false);
    } else {
        PM_CHECK("boot postmortem fork", true);
        int status = 0;
        pid_t got = waitpid(pid, &status, 0);
        PM_CHECK("boot postmortem wait child", got == pid);
        PM_CHECK("boot postmortem child SIGABRT",
                 got == pid && WIFSIGNALED(status) &&
                 WTERMSIG(status) == SIGABRT);

        struct postmortem_capsule_entry entries[1];
        size_t count = 0;
        int rc = postmortem_capsule_list(pm_dir, entries, 1, &count);
        PM_CHECK("boot postmortem capsule listed", rc == 0 && count == 1);
        PM_CHECK("boot postmortem signal recorded",
                 rc == 0 && count == 1 && entries[0].crash_signal == SIGABRT);
        if (rc == 0 && count == 1) {
            char proc_path[576];
            snprintf(proc_path, sizeof(proc_path), "%s/procstatus.txt",
                     entries[0].path);
#if defined(__linux__)
            PM_CHECK("boot postmortem proc status captured",
                     file_contains(proc_path, "Name:"));
#else
            PM_CHECK("boot postmortem proc status limitation recorded",
                      file_contains(proc_path,
                                    OS_SANDBOX_PROC_SELF_STATUS_PATH
                                    " is Linux-only"));
#endif
            char log_path[576];
            snprintf(log_path, sizeof(log_path), "%s/log.txt",
                     entries[0].path);
            PM_CHECK("boot postmortem log captured",
                     file_contains(log_path, "boot fatal breadcrumb"));
            seed_tape_t *loaded = postmortem_capsule_load_tape(entries[0].path);
            PM_CHECK("boot postmortem tape loads", loaded != NULL);
            if (loaded) {
                PM_CHECK("boot postmortem records boot event",
                         seed_tape_inject_count(loaded) == 1);
                uint8_t type = 0;
                char payload[64];
                size_t payload_len = 0;
                int ev_rc = seed_tape_next_event(loaded, &type, payload,
                                                 sizeof(payload),
                                                 &payload_len);
                PM_CHECK("boot postmortem replays boot event",
                         ev_rc == 0 && type == 1 &&
                         payload_len == strlen("boot-postmortem-installed") &&
                         memcmp(payload, "boot-postmortem-installed",
                                payload_len) == 0);
                seed_tape_close(loaded);
            }
        }
    }

    boot_postmortem_shutdown_for_testing();
    test_rm_rf_recursive(dir);
    return failures;
}

static int test_boot_postmortem_restart_compresses_prior_sigsegv(void)
{
    int failures = 0;
    char dir_template[128];
    snprintf(dir_template, sizeof(dir_template),
             "/tmp/zcl_boot_postmortem_restart_%d_XXXXXX", (int)getpid());
    char *dir = mkdtemp(dir_template);
    PM_CHECK("boot restart mkdtemp", dir != NULL);
    if (!dir) return failures + 1;

    char log_seed_path[256];
    snprintf(log_seed_path, sizeof(log_seed_path), "%s/node.log", dir);
    PM_CHECK("boot restart seed log",
             write_text_file(log_seed_path, "restart fatal breadcrumb\n"));

    bool ok = boot_postmortem_init_for_testing(dir);
    const char *pm_dir = boot_postmortem_dir_for_testing();
    PM_CHECK("boot restart initial init", ok && pm_dir != NULL);

    char pm_dir_copy[512];
    if (pm_dir) {
        snprintf(pm_dir_copy, sizeof(pm_dir_copy), "%s", pm_dir);
    } else {
        pm_dir_copy[0] = '\0';
    }

    pid_t pid = fork();
    if (pid == 0) {
        if (!ok || !pm_dir)
            _exit(121);
        raise(SIGSEGV);
        _exit(122);
    }

    if (pid < 0) {
        PM_CHECK("boot restart fork", false);
    } else {
        PM_CHECK("boot restart fork", true);
        int status = 0;
        pid_t got = waitpid(pid, &status, 0);
        PM_CHECK("boot restart wait child", got == pid);
        PM_CHECK("boot restart child SIGSEGV",
                 got == pid && WIFSIGNALED(status) &&
                 WTERMSIG(status) == SIGSEGV);
    }

    struct postmortem_capsule_entry entries[1];
    size_t count = 0;
    int rc = postmortem_capsule_list(pm_dir_copy, entries, 1, &count);
    PM_CHECK("boot restart prior capsule listed", rc == 0 && count == 1);
    PM_CHECK("boot restart prior capsule unpacked",
             rc == 0 && count == 1 &&
             strstr(entries[0].name, ".cap") != NULL &&
             strstr(entries[0].name, ".cap.gz") == NULL);
    if (rc == 0 && count == 1) {
        char proc_path[576];
        snprintf(proc_path, sizeof(proc_path), "%s/procstatus.txt",
                 entries[0].path);
#if defined(__linux__)
        PM_CHECK("boot restart proc status captured",
                 file_contains(proc_path, "Name:"));
#else
        PM_CHECK("boot restart proc status limitation recorded",
                  file_contains(proc_path,
                                OS_SANDBOX_PROC_SELF_STATUS_PATH
                                " is Linux-only"));
#endif
        char log_path[576];
        snprintf(log_path, sizeof(log_path), "%s/log.txt",
                 entries[0].path);
        PM_CHECK("boot restart log captured",
                 file_contains(log_path, "restart fatal breadcrumb"));
    }

    boot_postmortem_shutdown_for_testing();

    ok = boot_postmortem_init_for_testing(dir);
    pm_dir = boot_postmortem_dir_for_testing();
    PM_CHECK("boot restart second init", ok && pm_dir != NULL);
    rc = postmortem_capsule_list(pm_dir_copy, entries, 1, &count);
    PM_CHECK("boot restart compressed capsule listed",
             rc == 0 && count == 1);
    PM_CHECK("boot restart compressed capsule",
             rc == 0 && count == 1 &&
             strstr(entries[0].name, ".cap.gz") != NULL &&
             entries[0].crash_signal == SIGSEGV);
    if (rc == 0 && count == 1) {
        seed_tape_t *loaded = postmortem_capsule_load_tape(entries[0].path);
        PM_CHECK("boot restart compressed tape loads", loaded != NULL);
        if (loaded) {
            PM_CHECK("boot restart compressed tape has boot event",
                     seed_tape_inject_count(loaded) == 1);
            uint8_t type = 0;
            char payload[64];
            size_t payload_len = 0;
            int ev_rc = seed_tape_next_event(loaded, &type, payload,
                                             sizeof(payload), &payload_len);
            PM_CHECK("boot restart compressed replays boot event",
                     ev_rc == 0 && type == 1 &&
                     payload_len == strlen("boot-postmortem-installed") &&
                     memcmp(payload, "boot-postmortem-installed",
                            payload_len) == 0);
            seed_tape_close(loaded);
        }
    }

    boot_postmortem_shutdown_for_testing();
    test_rm_rf_recursive(dir);
    return failures;
}

static int test_capsule_prune(void)
{
    int failures = 0;
    char dir_template[128];
    snprintf(dir_template, sizeof(dir_template),
             "/tmp/zcl_postmortem_prune_%d_XXXXXX", (int)getpid());
    char *dir = mkdtemp(dir_template);
    PM_CHECK("prune mkdtemp", dir != NULL);
    if (!dir) return failures + 1;

    seed_tape_t *tape = seed_tape_open(0x5052554e45ULL, 1000);
    PM_CHECK("prune seed tape open", tape != NULL);
    if (!tape) {
        test_rm_rf_recursive(dir);
        return failures + 1;
    }

    struct postmortem_capture_opts opts = {
        .dir = dir,
        .tape = tape,
        .crash_signal = 6,
        .crash_unix = 0,
        .reason = "prune",
        .log_path = NULL,
    };
    const int64_t stamps[] = { 1000, 2000, 3000, 4000 };
    for (size_t i = 0; i < sizeof(stamps) / sizeof(stamps[0]); i++) {
        char path[512];
        opts.crash_unix = stamps[i];
        int rc = postmortem_capture_write(&opts, path, sizeof(path));
        PM_CHECK("prune seed capsule", rc == 0);
    }

    size_t pruned = 0;
    int rc = postmortem_capsule_prune(dir, 5000, 2500, 2, &pruned);
    PM_CHECK("prune age/count returns 0", rc == 0);
    PM_CHECK("prune removes older capsules", pruned == 2);

    struct postmortem_capsule_entry entries[4];
    size_t count = 0;
    rc = postmortem_capsule_list(dir, entries, 4, &count);
    PM_CHECK("prune list after age prune", rc == 0 && count == 2);
    PM_CHECK("prune kept newest two",
             rc == 0 && count == 2 &&
             entries[0].crash_unix == 4000 &&
             entries[1].crash_unix == 3000);

    pruned = 0;
    rc = postmortem_capsule_prune(dir, 5000, 999999, 1, &pruned);
    PM_CHECK("prune count-only returns 0", rc == 0);
    PM_CHECK("prune count-only removes one", pruned == 1);
    count = 0;
    rc = postmortem_capsule_list(dir, entries, 4, &count);
    PM_CHECK("prune count-only kept newest",
             rc == 0 && count == 1 && entries[0].crash_unix == 4000);

    seed_tape_close(tape);
    test_rm_rf_recursive(dir);
    return failures;
}

static int test_capsule_compress(void)
{
    int failures = 0;
    char dir_template[128];
    snprintf(dir_template, sizeof(dir_template),
             "/tmp/zcl_postmortem_compress_%d_XXXXXX", (int)getpid());
    char *dir = mkdtemp(dir_template);
    PM_CHECK("compress mkdtemp", dir != NULL);
    if (!dir) return failures + 1;

    seed_tape_t *tape = seed_tape_open(0x434f4d5052455353ULL, 1779667000);
    PM_CHECK("compress seed tape open", tape != NULL);
    if (!tape) {
        test_rm_rf_recursive(dir);
        return failures + 1;
    }
    seed_tape_advance(tape, 42);
    seed_tape_inject(tape, 99, "packed", 6);

    char cap_path[512];
    struct postmortem_capture_opts opts = {
        .dir = dir,
        .tape = tape,
        .crash_signal = 11,
        .crash_unix = 1779667123,
        .reason = "compress",
        .log_path = NULL,
    };
    int rc = postmortem_capture_write(&opts, cap_path, sizeof(cap_path));
    PM_CHECK("compress capture write", rc == 0);

    char gz_path[576];
    rc = postmortem_capsule_compress(cap_path, gz_path, sizeof(gz_path));
    PM_CHECK("compress returns 0", rc == 0);
    PM_CHECK("compress writes .cap.gz",
             rc == 0 && strstr(gz_path, ".cap.gz") != NULL);
    struct stat st;
    PM_CHECK("compress removes unpacked dir", stat(cap_path, &st) != 0);
    PM_CHECK("compress leaves archive",
             rc == 0 && stat(gz_path, &st) == 0 && S_ISREG(st.st_mode));
    PM_CHECK("compressed capsule validates",
             rc == 0 && postmortem_capsule_validate(gz_path));

    seed_tape_t *loaded = rc == 0 ? postmortem_capsule_load_tape(gz_path)
                                  : NULL;
    PM_CHECK("compressed tape loads", loaded != NULL);
    if (loaded) {
        PM_CHECK("compressed tape preserves inject count",
                 seed_tape_inject_count(loaded) == 1);
        seed_tape_close(loaded);
    }

    struct postmortem_capsule_entry entries[1];
    size_t count = 0;
    rc = postmortem_capsule_list(dir, entries, 1, &count);
    PM_CHECK("compressed capsule listed", rc == 0 && count == 1);
    PM_CHECK("compressed list metadata",
             rc == 0 && count == 1 &&
             strstr(entries[0].name, ".cap.gz") != NULL &&
             entries[0].crash_signal == 11 &&
             entries[0].tape_size_bytes == seed_tape_size_bytes(tape));

    opts.crash_unix = 1779667124;
    rc = postmortem_capture_write(&opts, cap_path, sizeof(cap_path));
    PM_CHECK("compress-unpacked seed capture", rc == 0);
    size_t compressed = 0;
    rc = postmortem_capsule_compress_unpacked(dir, &compressed);
    PM_CHECK("compress-unpacked returns 0", rc == 0);
    PM_CHECK("compress-unpacked archives one", compressed == 1);
    count = 0;
    struct postmortem_capsule_entry two_entries[2];
    rc = postmortem_capsule_list(dir, two_entries, 2, &count);
    PM_CHECK("compress-unpacked list sees two archives",
             rc == 0 && count == 2 &&
             strstr(two_entries[0].name, ".cap.gz") != NULL &&
             strstr(two_entries[1].name, ".cap.gz") != NULL);

    size_t pruned = 0;
    rc = postmortem_capsule_prune(dir, 1779668000, 1, 100, &pruned);
    PM_CHECK("compressed prune returns 0", rc == 0);
    PM_CHECK("compressed prune removes archives", pruned == 2);

    seed_tape_close(tape);
    test_rm_rf_recursive(dir);
    return failures;
}

static int test_postmortem_platform_arm(void)
{
    /* monolith isolation: a prior group leaves the node fatal-signal handlers
     * installed, which makes postmortem_install() refuse (it requires SIG_DFL)
     * and the fork-and-raise children below _exit instead of dying from the
     * signal. The shared reset restores SIG_DFL. See test_helpers.c. */
    test_reset_shared_globals();
    printf("\n=== postmortem tests ===\n");
    int failures = 0;

    char dir_template[128];
    snprintf(dir_template, sizeof(dir_template),
             "/tmp/zcl_postmortem_%d_XXXXXX", (int)getpid());
    char *dir = mkdtemp(dir_template);
    PM_CHECK("mkdtemp", dir != NULL);
    if (!dir) return failures + 1;

    char log_path[256];
    snprintf(log_path, sizeof(log_path), "%s/node.log", dir);
    FILE *lf = fopen(log_path, "wb");
    PM_CHECK("create source log", lf != NULL);
    if (lf) {
        fprintf(lf, "line one\nfatal breadcrumb\n");
        fclose(lf);
    }

    seed_tape_t *tape = seed_tape_open(0x12345678ULL, 1779665000);
    PM_CHECK("seed tape open", tape != NULL);
    if (tape) {
        seed_tape_advance(tape, 5000);
        seed_tape_inject(tape, 7, "abc", 3);
    }

    char cap_path[512];
    struct postmortem_capture_opts opts = {
        .dir = dir,
        .tape = tape,
        .crash_signal = 11,
        .crash_unix = 1779665123,
        .reason = "unit-test",
        .log_path = log_path,
    };
    int rc = postmortem_capture_write(&opts, cap_path, sizeof(cap_path));
    PM_CHECK("capture write returns 0", rc == 0);
    PM_CHECK("capsule validates", postmortem_capsule_validate(cap_path));

    char manifest_path[576];
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json",
             cap_path);
    PM_CHECK("manifest records signal",
             file_contains(manifest_path, "\"crash_signal\": 11"));
    PM_CHECK("manifest records reason",
             file_contains(manifest_path, "\"reason\": \"unit-test\""));
    PM_CHECK("manifest records build id",
             file_contains(manifest_path, "\"build_id\": \"ZClassic23-"));
    PM_CHECK("manifest records git sha placeholder",
             file_contains(manifest_path, "\"git_sha\": \"unknown\""));

    char regs_path[576];
    snprintf(regs_path, sizeof(regs_path), "%s/registers.txt", cap_path);
    PM_CHECK("non-signal register placeholder written",
             file_contains(regs_path, "non-signal capture"));

    char copied_log_path[576];
    snprintf(copied_log_path, sizeof(copied_log_path), "%s/log.txt",
             cap_path);
    PM_CHECK("log tail copied",
             file_contains(copied_log_path, "fatal breadcrumb"));

    seed_tape_t *loaded = postmortem_capsule_load_tape(cap_path);
    PM_CHECK("load tape from capsule", loaded != NULL);
    if (loaded) {
        PM_CHECK("loaded tape preserves inject count",
                 seed_tape_inject_count(loaded) == 1);
        seed_tape_close(loaded);
    }

    char cap_path_old[512];
    opts.crash_unix = 1779665001;
    opts.crash_signal = 6;
    opts.reason = "older";
    rc = postmortem_capture_write(&opts, cap_path_old, sizeof(cap_path_old));
    PM_CHECK("older capture write returns 0", rc == 0);

    char cap_path_new[512];
    opts.crash_unix = 1779665999;
    opts.crash_signal = 8;
    opts.reason = "newer";
    rc = postmortem_capture_write(&opts, cap_path_new, sizeof(cap_path_new));
    PM_CHECK("newer capture write returns 0", rc == 0);

    struct postmortem_capsule_entry entries[2];
    size_t count = 0;
    rc = postmortem_capsule_list(dir, entries, 2, &count);
    PM_CHECK("list returns 0", rc == 0);
    PM_CHECK("list sees three capsules", count == 3);
    PM_CHECK("list returns newest first within cap",
             count >= 3 &&
             entries[0].crash_unix == 1779665999 &&
             entries[1].crash_unix == 1779665123);
    PM_CHECK("list parses manifest summary",
             entries[0].crash_signal == 8 &&
             entries[0].tape_size_bytes == seed_tape_size_bytes(tape));

    struct postmortem_summary summaries[2];
    size_t summary_count = 0;
    rc = postmortem_list(dir, summaries, 2, &summary_count);
    PM_CHECK("summary list returns 0", rc == 0);
    PM_CHECK("summary list mirrors ordering",
             summary_count == 3 &&
             summaries[0].crash_unix == 1779665999 &&
             summaries[1].crash_unix == 1779665123);
    PM_CHECK("summary includes capsule bytes",
             summaries[0].capsule_bytes > summaries[0].tape_size_bytes);

    seed_tape_t *loaded_alias = postmortem_load(cap_path_new);
    PM_CHECK("postmortem_load alias decodes tape", loaded_alias != NULL);
    if (loaded_alias) seed_tape_close(loaded_alias);

    char tape_path[576];
    snprintf(tape_path, sizeof(tape_path), "%s/tape.bin", cap_path);
    int fd = open(tape_path, O_RDWR);
    PM_CHECK("open tape for corruption", fd >= 0);
    if (fd >= 0) {
        unsigned char b = 0;
        ssize_t got = pread(fd, &b, 1, 40);
        b ^= 0xff;
        ssize_t wrote = pwrite(fd, &b, 1, 40);
        close(fd);
        PM_CHECK("corrupt tape byte", got == 1 && wrote == 1);
        PM_CHECK("corrupt capsule rejected",
                 !postmortem_capsule_validate(cap_path));
    }

    PM_CHECK("NULL opts rejected",
             postmortem_capture_write(NULL, NULL, 0) == -EINVAL);

    seed_tape_close(tape);
    test_rm_rf_recursive(dir);
    failures += test_capsule_compress();
    failures += test_capsule_prune();
    failures += test_postmortem_install_validates_dir();
    failures += test_signal_handler_capsule();
    failures += test_boot_postmortem_install();
    failures += test_boot_postmortem_restart_compresses_prior_sigsegv();

    if (failures == 0)
        printf("=== postmortem tests: ALL PASS ===\n\n");
    else
        printf("postmortem: failures=%d\n", failures);
    return failures;
}
#else  /* _WIN32 */
/* The postmortem capsule machinery is POSIX fatal-signal based (sigaction
 * handlers, fork-and-raise children, core dumps). AGENTS.md records
 * signal-context self-backtraces as unavailable on the Windows lane. */
static int test_postmortem_platform_arm(void)
{
    printf("postmortem: SKIP (Windows): POSIX fatal-signal capsule lane "
           "(sigaction + fork-and-raise) has no Windows analogue\n");
    return 0;
}
#endif

int test_postmortem(void)
{
    return test_postmortem_platform_arm();
}
