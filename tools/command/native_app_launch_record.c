/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the launcher's pid record, <state_dir>/<id>.pid. It is the one
 * application write `z23 app open` makes, so it follows the ActiveRecord
 * save lifecycle (validate -> before_save -> durable write -> after_save):
 * an exclusive owner-private sibling is written and fsynced, renamed over
 * the record, and the directory is fsynced. A record names pid, kernel
 * start time and executable; a reader trusts it only when all three still
 * match a live process, which defeats pid reuse. */

#include "command/native_app_launch.h"

#include "models/activerecord.h"
#include "platform/file_sync.h"
#include "util/log_macros.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define APP_RECORD_SCHEMA "zcl.app_pid.v1"
#define APP_RECORD_MAX 2048u

struct ar_callbacks *db_app_launch_record_callbacks(void);
DEFINE_MODEL_CALLBACKS(app_launch_record)

static bool app_record_text_ok(const char *s)
{
    for (; *s; s++)
        if ((unsigned char)*s < 0x20 || *s == 0x7f)
            return false;
    return true;
}

static bool app_record_validate(const struct app_launch_record *rec,
                                struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_custom(errors, rec->id[0] && strlen(rec->id) <= APP_LAUNCH_ID_MAX,
                     "id", "must be 1-32 bytes");
    validates_custom(errors, strspn(rec->id, "abcdefghijklmnopqrstuvwxyz"
                                             "0123456789-") == strlen(rec->id),
                     "id", "must be a-z, 0-9 and -");
    validates_custom(errors, rec->pid > 1, "pid", "must be a process id");
    validates_custom(errors, rec->start_time > 0, "start_time",
                     "must be the kernel start time");
    validates_custom(errors, rec->executable[0] == '/', "executable",
                     "must be absolute");
    validates_custom(errors, app_record_text_ok(rec->executable), "executable",
                     "must not hold control bytes");
    return !ar_errors_any(errors);
}

/* The public functions are defined once, at the end of this file; the
 * per-platform bodies are static helpers. */
#if defined(_WIN32)

static bool app_os_state_dir_ready(const char *state_dir)
{
    (void)state_dir;
    errno = ENOSYS;
    return false;
}

static bool app_record_write(const char *state_dir,
                             const struct app_launch_record *rec)
{
    (void)state_dir; (void)rec;
    errno = ENOSYS;
    return false;
}

static bool app_os_record_load(const char *state_dir, const char *id,
                               struct app_launch_record *rec)
{
    (void)state_dir; (void)id; (void)rec;
    return false;
}

#else

static bool app_os_state_dir_ready(const char *state_dir)
{
    char path[APP_LAUNCH_PATH_MAX];
    size_t len = strlen(state_dir);
    if (state_dir[0] != '/' || len >= sizeof(path)) {
        errno = EINVAL;
        return false;
    }
    memcpy(path, state_dir, len + 1);
    for (char *p = path + 1;; p++) {
        if (*p != '/' && *p != '\0')
            continue;
        char saved = *p;
        *p = '\0';
        if (mkdir(path, 0700) != 0 && errno != EEXIST)
            return false;
        *p = saved;
        if (saved == '\0')
            break;
    }
    struct stat st;
    return stat(state_dir, &st) == 0 && S_ISDIR(st.st_mode) &&
           st.st_uid == getuid();
}

static bool app_record_path(char *out, size_t cap, const char *state_dir,
                            const char *id, const char *suffix)
{
    int n = snprintf(out, cap, "%s/%s%s", state_dir, id, suffix);
    return n > 0 && (size_t)n < cap;
}

static bool app_write_all(int fd, const char *text, size_t len)
{
    while (len) {
        ssize_t n = write(fd, text, len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        text += n;
        len -= (size_t)n;
    }
    return true;
}

static bool app_dir_sync(const char *dir)
{
    int fd = open(dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (fd < 0)
        return false;
    bool ok = platform_file_sync(fd) == 0;
    (void)close(fd);
    return ok;
}

/* Private sibling -> fsync -> rename -> directory fsync. */
static bool app_record_write(const char *state_dir,
                             const struct app_launch_record *rec)
{
    char text[APP_RECORD_MAX], tmp[APP_LAUNCH_PATH_MAX], dst[APP_LAUNCH_PATH_MAX];
    char suffix[48];
    int n = snprintf(text, sizeof(text),
                     APP_RECORD_SCHEMA "\npid=%ld\nstart_time=%llu\n"
                     "executable=%s\n", rec->pid,
                     (unsigned long long)rec->start_time, rec->executable);
    snprintf(suffix, sizeof(suffix), ".pid.tmp.%ld", (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof(text) ||
        !app_record_path(tmp, sizeof(tmp), state_dir, rec->id, suffix) ||
        !app_record_path(dst, sizeof(dst), state_dir, rec->id, ".pid"))
        return false;
    (void)unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                  0600);
    if (fd < 0)
        return false;
    bool ok = app_write_all(fd, text, (size_t)n) && platform_file_sync(fd) == 0;
    ok = close(fd) == 0 && ok;
    ok = ok && rename(tmp, dst) == 0;
    if (!ok) {
        LOG_ERROR("app-launch", "pid record %s not written: %s", dst,
                  strerror(errno));
        (void)unlink(tmp);
        return false;
    }
    if (!app_dir_sync(state_dir)) {
        LOG_ERROR("app-launch", "pid record %s: directory fsync failed: %s",
                  dst, strerror(errno));
        return false;
    }
    return true;
}

static bool app_record_field(struct app_launch_record *rec, const char *line)
{
    char *end = NULL;
    errno = 0;
    if (strncmp(line, "pid=", 4) == 0) {
        rec->pid = strtol(line + 4, &end, 10);
        return errno == 0 && end && *end == '\0';
    }
    if (strncmp(line, "start_time=", 11) == 0) {
        rec->start_time = (uint64_t)strtoull(line + 11, &end, 10);
        return errno == 0 && end && *end == '\0';
    }
    if (strncmp(line, "executable=", 11) == 0) {
        size_t len = strlen(line + 11);
        if (len >= sizeof(rec->executable))
            return false;
        memcpy(rec->executable, line + 11, len + 1);
        return true;
    }
    return false;
}

static bool app_record_parse(struct app_launch_record *rec, char *text)
{
    char *save = NULL;
    char *line = strtok_r(text, "\n", &save);
    if (!line || strcmp(line, APP_RECORD_SCHEMA) != 0)
        return false;
    while ((line = strtok_r(NULL, "\n", &save)))
        if (!app_record_field(rec, line))
            return false;
    struct ar_errors errors;
    return app_record_validate(rec, &errors);
}

static bool app_os_record_load(const char *state_dir, const char *id,
                               struct app_launch_record *rec)
{
    char path[APP_LAUNCH_PATH_MAX], text[APP_RECORD_MAX];
    memset(rec, 0, sizeof(*rec));
    if (strlen(id) > APP_LAUNCH_ID_MAX ||
        !app_record_path(path, sizeof(path), state_dir, id, ".pid"))
        return false;
    memcpy(rec->id, id, strlen(id) + 1);
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    ssize_t n = read(fd, text, sizeof(text) - 1);
    (void)close(fd);
    if (n <= 0)
        return false;
    text[n] = '\0';
    return app_record_parse(rec, text);
}

#endif /* !_WIN32 */

/* ── public entry points: one definition each ─────────────────────────── */

bool app_launch_state_dir_ready(const char *state_dir)
{
    return app_os_state_dir_ready(state_dir);
}

bool app_launch_record_save(const char *state_dir,
                            const struct app_launch_record *rec)
{
    struct ar_callbacks *cbs = db_app_launch_record_callbacks();
    if (!state_dir || !rec)
        return false;
    AR_BEGIN_SAVE(cbs, "app_launch_record", rec, app_record_validate);
    bool ok = app_record_write(state_dir, rec);
    AR_FINISH_SAVE(cbs, rec, ok);
}

bool app_launch_record_load(const char *state_dir, const char *id,
                            struct app_launch_record *rec)
{
    return app_os_record_load(state_dir, id, rec);
}
