/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Single-writer admission for the selected datadir: take a nonblocking OS
 * lock on <datadir>/zclassic23.pid, or refuse the boot with a typed reason.
 * Every refusal here is rendered through boot_error_report (config/
 * boot_error.h) because this runs long before the command registry exists —
 * an operator or agent gets {code, phase, message, evidence, next[]} in the
 * same shape a dispatched command would give them. */

#include "config/boot_datadir_lock.h"

#include "config/boot_error.h"
#include "util/hw_bench.h"
#include "util/storage_pacing.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BDL_PIDFILE "zclassic23.pid"
#define BDL_PHASE   "datadir_lock"

#if defined(_WIN32)

#include "platform/private_directory.h"
#include "platform/private_file.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

static HANDLE g_datadir_handle = INVALID_HANDLE_VALUE;
static struct platform_private_file g_pidfile;
static bool g_pidfile_initialized;

bool boot_datadir_lock_acquire(const char *datadir)
{
    if (!datadir || !datadir[0]) {
        boot_error_report(BOOT_ERROR_FATAL, "BOOT_DATADIR_UNSET", BDL_PHASE,
                          "no data directory was resolved", NULL, 0,
                          "datadir=%s", datadir ? "(empty string)" : "(null)");
        return false;
    }
    if (g_datadir_handle != INVALID_HANDLE_VALUE) {
        boot_error_report(BOOT_ERROR_FATAL, "BOOT_DATADIR_LOCK_REENTERED",
                          BDL_PHASE,
                          "this process already holds a datadir lock", NULL, 0,
                          "datadir=%s pid=%lu", datadir,
                          (unsigned long)GetCurrentProcessId());
        return false;
    }

    uintptr_t directory_native = (uintptr_t)INVALID_HANDLE_VALUE;
    if (!platform_private_directory_open_validated(datadir,
                                                   &directory_native)) {
        boot_error_report(BOOT_ERROR_FATAL, "BOOT_DATADIR_NOT_PRIVATE",
                          BDL_PHASE,
                          "the Windows datadir must be a real owner-private directory",
                          NULL, 0, "datadir=%s", datadir);
        return false;
    }
    HANDLE directory = (HANDLE)directory_native;

    char pidpath[32768];
    int n = snprintf(pidpath, sizeof(pidpath), "%s/%s", datadir, BDL_PIDFILE);
    platform_private_file_init(&g_pidfile);
    g_pidfile_initialized = true;
    if (n <= 0 || (size_t)n >= sizeof(pidpath) ||
        !platform_private_file_open_locked_create(pidpath, &g_pidfile)) {
        DWORD lock_err = GetLastError();
        platform_private_file_close(&g_pidfile);
        g_pidfile_initialized = false;
        platform_private_directory_close(directory_native);
        boot_error_report(BOOT_ERROR_FATAL, "BOOT_DATADIR_LOCKED", BDL_PHASE,
                          "another process holds the datadir or its private lock file is invalid",
                          NULL, 0, "datadir=%s lockfile=%s windows_error=%lu",
                          datadir, BDL_PIDFILE, (unsigned long)lock_err);
        return false;
    }

    char text[32];
    int length = snprintf(text, sizeof(text), "%lu\n",
                          (unsigned long)GetCurrentProcessId());
    if (length <= 0 || (size_t)length >= sizeof(text) ||
        !platform_private_file_truncate(&g_pidfile, 0) ||
        !platform_private_file_write_at(&g_pidfile, text, (size_t)length, 0) ||
        !platform_private_file_flush(&g_pidfile) ||
        !FlushFileBuffers(directory)) {
        platform_private_file_close(&g_pidfile);
        g_pidfile_initialized = false;
        platform_private_directory_close(directory_native);
        boot_error_report(BOOT_ERROR_FATAL,
                          "BOOT_DATADIR_LOCK_PERSIST_FAILED", BDL_PHASE,
                          "the datadir lock could not be durably recorded",
                          NULL, 0, "datadir=%s lockfile=%s", datadir,
                          BDL_PIDFILE);
        return false;
    }
    g_datadir_handle = directory;
    hw_bench_init(datadir);
    /* Right after hw_bench, for the same reason: classify the datadir
     * storage ONCE, here, so every later bound (WAL truncation, log
     * rotation, projection compaction, boot readahead) reads a decision
     * that is already made rather than probing from its own hot path.
     * hw_bench has just run, so its measured pread median is available as
     * free evidence and the dedicated probe usually never fires. */
    storage_pacing_init(datadir);
    return true;
}

void boot_datadir_lock_release(void)
{
    if (g_pidfile_initialized) {
        platform_private_file_close(&g_pidfile);
        g_pidfile_initialized = false;
    }
    if (g_datadir_handle != INVALID_HANDLE_VALUE) {
        platform_private_directory_close((uintptr_t)g_datadir_handle);
        g_datadir_handle = INVALID_HANDLE_VALUE;
    }
}

#else

static int g_pidfile_fd = -1;

static bool write_all(int fd, const char *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        return false;
    }
    return true;
}

static long lock_holder_pid(int fd)
{
    char buf[32] = {0};
    ssize_t n;
    do {
        n = pread(fd, buf, sizeof(buf) - 1, 0);
    } while (n < 0 && errno == EINTR);
    if (n <= 0)
        return 0;

    char *end = NULL;
    errno = 0;
    long pid = strtol(buf, &end, 10);
    if (errno != 0 || end == buf || pid <= 0)
        return 0;
    return pid;
}

/* The suggestion every "this datadir is unavailable" refusal shares: a second
 * node needs a second datadir. Always true, always runnable. */
static const char *const k_second_instance_reason =
    "a second node instance needs its OWN data directory; two processes "
    "writing one datadir corrupt the SQLite and LevelDB stores";

bool boot_datadir_lock_acquire(const char *datadir)
{
    if (!datadir || !*datadir) {
        const struct boot_error_next next[] = {
            { "zclassic23 -datadir=/path/to/datadir",
              "name the data directory explicitly; an empty -datadir= value "
              "resolves to nothing and the default only applies when the flag "
              "is absent entirely" },
        };
        boot_error_report(BOOT_ERROR_FATAL, "BOOT_DATADIR_UNSET", BDL_PHASE,
                          "no data directory was resolved, so the "
                          "single-writer lock cannot be taken",
                          next, 1, "datadir=%s",
                          datadir ? "(empty string)" : "(null)");
        return false;
    }
    if (g_pidfile_fd >= 0) {
        /* No next[]: this is an internal ordering violation, not an operator
         * condition. Naming a command would be a guess. */
        boot_error_report(BOOT_ERROR_FATAL, "BOOT_DATADIR_LOCK_REENTERED",
                          BDL_PHASE,
                          "this process already holds a datadir lock — "
                          "boot_datadir_lock_acquire is not re-entrant and a "
                          "second call would leak the first descriptor",
                          NULL, 0, "datadir=%s held_fd=%d pid=%ld",
                          datadir, g_pidfile_fd, (long)getpid());
        return false;
    }

    int dir_fd = open(datadir,
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dir_fd < 0) {
        int e = errno;
        char parent[1024];
        (void)snprintf(parent, sizeof(parent), "%s", datadir);
        char *slash = strrchr(parent, '/');
        if (slash && slash != parent)
            *slash = '\0';
        else if (slash)
            (void)snprintf(parent, sizeof(parent), "/");
        else
            (void)snprintf(parent, sizeof(parent), ".");

        char mk[1100], ls[1100], rl[1100];
        (void)snprintf(mk, sizeof(mk), "mkdir -p %s", datadir);
        (void)snprintf(ls, sizeof(ls), "ls -ld %s", parent);
        (void)snprintf(rl, sizeof(rl), "readlink -f %s", datadir);

        /* MEASURED, not assumed: on Linux, open(O_DIRECTORY|O_NOFOLLOW) over a
         * symlink-to-directory reports ENOTDIR, not the ELOOP that POSIX
         * describes — the final component is the link itself, and a link is
         * not a directory. Classifying ENOTDIR as "this path is a file" would
         * tell the operator to point -datadir= at a directory when it already
         * is one. lstat settles which case this actually is. */
        struct stat lst;
        bool path_stats = lstat(datadir, &lst) == 0;
        bool is_symlink = path_stats && S_ISLNK(lst.st_mode);

        if (e == ELOOP || (e == ENOTDIR && is_symlink)) {
            /* O_NOFOLLOW: the path itself is a symlink. Following it would
             * let the datadir be swapped underneath a running node. */
            const struct boot_error_next next[] = {
                { rl, "resolve the link and pass the real directory with "
                      "-datadir=; zclassic23 opens the datadir with O_NOFOLLOW "
                      "so the target cannot be swapped under a running node" },
            };
            boot_error_report(BOOT_ERROR_FATAL,
                              "BOOT_DATADIR_SYMLINK_REFUSED", BDL_PHASE,
                              "the -datadir path is a symbolic link; "
                              "zclassic23 refuses to follow it",
                              next, 1,
                              "datadir=%s is_symlink=true open_errno=%s",
                              datadir, strerror(e));
        } else if (e == ENOENT) {
            /* boot already attempted a single-level mkdir before this point
             * (boot_step_select_chain_and_datadir); reaching ENOENT here
             * means that attempt also failed — usually a missing parent. */
            const struct boot_error_next next[] = {
                { mk, "create the directory INCLUDING its parents; the node's "
                      "own create attempt is single-level and fails when a "
                      "parent is missing" },
                { ls, "confirm the parent directory exists and is writable by "
                      "the user running the node" },
            };
            boot_error_report(BOOT_ERROR_FATAL, "BOOT_DATADIR_MISSING",
                              BDL_PHASE,
                              "the data directory does not exist and the "
                              "node could not create it",
                              next, 2, "datadir=%s parent=%s open_errno=%s",
                              datadir, parent, strerror(e));
        } else if (e == EACCES || e == EPERM) {
            /* List the PARENT as well as the datadir: a denial is just as
             * often a parent without +x, and `ls -ld <datadir>` alone would
             * then fail the same way and tell the reader nothing new. */
            char lsd[2200];
            (void)snprintf(lsd, sizeof(lsd), "ls -ld %s %s", parent, datadir);
            const struct boot_error_next next[] = {
                { lsd, "compare the owner and mode of the datadir AND its "
                       "parent against the user running the node; a missing "
                       "+x on the parent denies the datadir too" },
                { "id -un", "print the user this process runs as" },
            };
            boot_error_report(BOOT_ERROR_FATAL, "BOOT_DATADIR_UNREADABLE",
                              BDL_PHASE,
                              "the data directory exists but this user cannot "
                              "open it",
                              next, 2, "datadir=%s uid=%ld open_errno=%s",
                              datadir, (long)getuid(), strerror(e));
        } else if (e == ENOTDIR) {
            /* ENOTDIR covers two different mistakes: the path itself is a
             * file, or some PARENT component is. lstat distinguishes them —
             * telling an operator "-datadir= points at a file" when the file
             * is three components up sends them to the wrong place. */
            char lsd[1100];
            (void)snprintf(lsd, sizeof(lsd), "ls -ld %s",
                           path_stats ? datadir : parent);
            const struct boot_error_next final_is_file[] = {
                { lsd, "the -datadir path itself is a file — point -datadir= "
                       "at a directory" },
            };
            const struct boot_error_next component_is_file[] = {
                { lsd, "a PARENT component of the -datadir path is a file, so "
                       "the path can never resolve; this lists the nearest "
                       "one" },
            };
            boot_error_report(BOOT_ERROR_FATAL,
                              "BOOT_DATADIR_NOT_A_DIRECTORY", BDL_PHASE,
                              path_stats
                                  ? "the -datadir path exists but is not a "
                                    "directory"
                                  : "a component of the -datadir path is not "
                                    "a directory, so the path cannot resolve",
                              path_stats ? final_is_file : component_is_file,
                              1, "datadir=%s path_lstat=%s open_errno=%s",
                              datadir, path_stats ? "ok" : "failed",
                              strerror(e));
        } else {
            const struct boot_error_next next[] = {
                { ls, "inspect the parent directory; the open failed for a "
                      "reason other than missing/denied/not-a-directory" },
            };
            boot_error_report(BOOT_ERROR_FATAL, "BOOT_DATADIR_OPEN_FAILED",
                              BDL_PHASE,
                              "the data directory could not be opened",
                              next, 1, "datadir=%s open_errno=%s",
                              datadir, strerror(e));
        }
        return false;
    }

    int fd = openat(dir_fd, BDL_PIDFILE,
                    O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
                    0600);
    if (fd < 0) {
        int e = errno;
        close(dir_fd);
        char ls[1100];
        (void)snprintf(ls, sizeof(ls), "ls -l %s/%s", datadir, BDL_PIDFILE);
        const struct boot_error_next next[] = {
            { ls, e == ELOOP
                      ? "the lock file is a symlink; zclassic23 opens it with "
                        "O_NOFOLLOW and refuses. Remove the link only after "
                        "confirming no node is running"
                      : "inspect the lock file's owner and mode" },
        };
        boot_error_report(BOOT_ERROR_FATAL,
                          "BOOT_DATADIR_LOCKFILE_OPEN_FAILED", BDL_PHASE,
                          "the datadir lock file could not be opened or "
                          "created",
                          next, 1, "datadir=%s lockfile=%s open_errno=%s",
                          datadir, BDL_PIDFILE, strerror(e));
        return false;
    }

    struct stat st;
    int stat_rc = fstat(fd, &st);
    if (stat_rc != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1) {
        int e = stat_rc != 0 ? errno : EINVAL;
        unsigned long mode = stat_rc == 0 ? (unsigned long)st.st_mode : 0;
        unsigned long links = stat_rc == 0 ? (unsigned long)st.st_nlink : 0;
        close(fd);
        close(dir_fd);
        char ls[1100];
        (void)snprintf(ls, sizeof(ls), "ls -li %s/%s", datadir, BDL_PIDFILE);
        const struct boot_error_next next[] = {
            { ls, "a lock file with extra hard links or a non-regular type "
                  "can be observed or replaced by another user; replace it "
                  "only after confirming no node is running" },
        };
        boot_error_report(BOOT_ERROR_FATAL,
                          "BOOT_DATADIR_LOCKFILE_NOT_PRIVATE", BDL_PHASE,
                          "the datadir lock file is not a private regular "
                          "file, so holding a lock on it proves nothing",
                          next, 1,
                          "datadir=%s lockfile=%s st_mode=0%lo nlink=%lu "
                          "stat_errno=%s",
                          datadir, BDL_PIDFILE, mode, links, strerror(e));
        return false;
    }

    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        int e = errno;
        long holder = lock_holder_pid(fd);
        close(fd);
        close(dir_fd);
        if (e == EWOULDBLOCK || e == EAGAIN) {
            char ps[128], ls[1100];
            (void)snprintf(ps, sizeof(ps), "ps -o pid,lstart,cmd -p %ld",
                           holder);
            (void)snprintf(ls, sizeof(ls), "ls -l %s/%s", datadir,
                           BDL_PIDFILE);
            if (holder > 0) {
                const struct boot_error_next next[] = {
                    { ps, "identify the process that holds the lock before "
                          "stopping anything; it is normally the node service "
                          "for this datadir" },
                    { "zclassic23 -datadir=/path/to/other/datadir",
                      k_second_instance_reason },
                };
                boot_error_report(BOOT_ERROR_FATAL, "BOOT_DATADIR_LOCKED",
                                  BDL_PHASE,
                                  "another process already holds this data "
                                  "directory",
                                  next, 2,
                                  "datadir=%s holder_pid=%ld lockfile=%s",
                                  datadir, holder, BDL_PIDFILE);
            } else {
                const struct boot_error_next next[] = {
                    { ls, "the lock file records the owning PID but was empty "
                          "or unparseable here; its mtime still dates the "
                          "holder's start" },
                    { "zclassic23 -datadir=/path/to/other/datadir",
                      k_second_instance_reason },
                };
                boot_error_report(BOOT_ERROR_FATAL, "BOOT_DATADIR_LOCKED",
                                  BDL_PHASE,
                                  "another process already holds this data "
                                  "directory and did not record a readable "
                                  "PID",
                                  next, 2,
                                  "datadir=%s holder_pid=unknown lockfile=%s",
                                  datadir, BDL_PIDFILE);
            }
        } else {
            char stfs[1100];
            (void)snprintf(stfs, sizeof(stfs), "stat -f -c %%T %s", datadir);
            const struct boot_error_next next[] = {
                { stfs, "print the filesystem type: flock is unsupported or "
                        "unreliable on several network filesystems, and the "
                        "datadir must live on a local one" },
            };
            boot_error_report(BOOT_ERROR_FATAL, "BOOT_DATADIR_LOCK_FAILED",
                              BDL_PHASE,
                              "the datadir lock could not be taken for a "
                              "reason other than contention",
                              next, 1, "datadir=%s flock_errno=%s",
                              datadir, strerror(e));
        }
        return false;
    }

    char pid_text[32];
    int pid_len = snprintf(pid_text, sizeof(pid_text), "%ld\n",
                           (long)getpid());
    bool pid_fits = pid_len > 0 && (size_t)pid_len < sizeof(pid_text);
    if (!pid_fits)
        errno = EOVERFLOW;
    bool recorded = pid_fits && ftruncate(fd, 0) == 0 &&
                    lseek(fd, 0, SEEK_SET) == 0 &&
                    write_all(fd, pid_text, (size_t)pid_len) && fsync(fd) == 0 &&
                    fsync(dir_fd) == 0;
    if (!recorded) {
        int e = errno ? errno : EIO;
        (void)flock(fd, LOCK_UN);
        close(fd);
        close(dir_fd);
        char df[1100];
        (void)snprintf(df, sizeof(df), "df -h %s", datadir);
        const struct boot_error_next next[] = {
            { df, "check free space and the mount's read-only state; the lock "
                  "was taken but its PID could not be written and fsynced, so "
                  "the boot fails closed rather than run unrecorded" },
        };
        boot_error_report(BOOT_ERROR_FATAL,
                          "BOOT_DATADIR_LOCK_PERSIST_FAILED", BDL_PHASE,
                          "the datadir lock could not be durably recorded",
                          next, 1, "datadir=%s lockfile=%s write_errno=%s",
                          datadir, BDL_PIDFILE, strerror(e));
        return false;
    }

    close(dir_fd);
    g_pidfile_fd = fd;

    /* This is the earliest point boot has exclusive, safe possession of the
     * datadir — before crypto/wallet/progress-store setup and well before
     * the block-ingest reducer can ever run. Kick the hardware-bench
     * organ's one-time (possibly synchronous, up to ~300ms) fsync/pread
     * probe HERE so hw_bench_batch_size() (reducer_drain.c, called on
     * every reducer_kick under ctl->mutex) never has to run it lazily on
     * that hot path — see hw_bench.h's CALLER CONTRACT. Idempotent: a
     * concurrent/earlier hw_bench_init() (e.g. bg_validation_init) just
     * observes the cached result. */
    hw_bench_init(datadir);
    /* Right after hw_bench, for the same reason: classify the datadir
     * storage ONCE, here, so every later bound (WAL truncation, log
     * rotation, projection compaction, boot readahead) reads a decision
     * that is already made rather than probing from its own hot path.
     * hw_bench has just run, so its measured pread median is available as
     * free evidence and the dedicated probe usually never fires. */
    storage_pacing_init(datadir);

    return true;
}

void boot_datadir_lock_release(void)
{
    if (g_pidfile_fd < 0)
        return;

    int fd = g_pidfile_fd;
    g_pidfile_fd = -1;
    if (flock(fd, LOCK_UN) != 0) {
        fprintf(stderr, "[boot] Cannot explicitly unlock data directory: %s\n",
                strerror(errno));
    }
    if (close(fd) != 0) {
        fprintf(stderr, "[boot] Cannot close datadir lock descriptor: %s\n",
                strerror(errno));
    }
}

#endif
