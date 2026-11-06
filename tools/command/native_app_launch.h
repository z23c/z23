/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: `z23 app open` — the native desktop launcher. A launchable app is
 * a compiled-in row (app_launch_catalog.def, executable resolved only beside
 * the running z23 binary) or a row of the operator's own
 * $XDG_CONFIG_HOME/z23/apps.tsv (absolute path, fixed argv, no shell). The
 * launcher spawns it detached, waits for its ready marker, and remembers the
 * pid in an owner-private record so a second open finds the same process
 * instead of starting another copy, and raises its window with SIGUSR1 only
 * when the app's entry declares raise support.
 *
 * Every function takes an explicit app_launch_env so tests can point the
 * executable directory, config file and state directory at fixtures without
 * an environment override reaching production resolution. */

#ifndef ZCL_TOOLS_NATIVE_APP_LAUNCH_H
#define ZCL_TOOLS_NATIVE_APP_LAUNCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define APP_LAUNCH_ID_MAX 32u
#define APP_LAUNCH_ALIASES_MAX 4u
#define APP_LAUNCH_ARGS_MAX 8u
#define APP_LAUNCH_ARG_MAX 256u
#define APP_LAUNCH_MARKER_MAX 128u
#define APP_LAUNCH_HINT_MAX 96u
#define APP_LAUNCH_ENTRIES_MAX 16u
#define APP_LAUNCH_PATH_MAX 1024u
#define APP_LAUNCH_TAIL_MAX 1024u
#define APP_LAUNCH_READY_TIMEOUT_MS 15000
#define APP_LAUNCH_SETTLE_MS 1000

struct app_launch_entry {
    char id[APP_LAUNCH_ID_MAX + 1];
    char aliases[APP_LAUNCH_ALIASES_MAX][APP_LAUNCH_ID_MAX + 1];
    unsigned alias_count;
    char executable[APP_LAUNCH_PATH_MAX]; /* absolute; "" when unresolved */
    char args[APP_LAUNCH_ARGS_MAX][APP_LAUNCH_ARG_MAX];
    unsigned arg_count;
    char ready_marker[APP_LAUNCH_MARKER_MAX]; /* "" = alive after settle */
    char build_hint[APP_LAUNCH_HINT_MAX];
    bool raise_sigusr1; /* the app declares a SIGUSR1 bring-to-front handler */
    bool builtin;
    bool installed;
};

/* What a second open did to the running copy's window. */
enum app_raise_outcome {
    APP_RAISE_NONE,               /* not an already_open result */
    APP_RAISE_DELIVERED,          /* declared, handler present, SIGUSR1 sent */
    APP_RAISE_UNSUPPORTED_BY_APP, /* the entry declares no raise; not sent */
    APP_RAISE_NO_HANDLER,         /* declared, but this copy has no handler */
    APP_RAISE_FAILED,             /* the signal could not be checked or sent */
};

struct app_launch_env {
    char bin_dir[APP_LAUNCH_PATH_MAX];     /* "" = unknown: builtins absent */
    char config_path[APP_LAUNCH_PATH_MAX]; /* "" = no operator file */
    char state_dir[APP_LAUNCH_PATH_MAX];
    bool desktop;
    int ready_timeout_ms;
    int settle_ms;
};

struct app_launch_registry {
    struct app_launch_entry entries[APP_LAUNCH_ENTRIES_MAX];
    unsigned count;
    bool config_present;   /* the operator file exists */
    char config_error[256]; /* non-empty: the whole file was refused */
};

enum app_open_status {
    APP_OPEN_OPENED,
    APP_OPEN_ALREADY_OPEN,
    APP_OPEN_FAILED,
};

enum app_open_stage {
    APP_STAGE_NONE,
    APP_STAGE_UNKNOWN_APP,
    APP_STAGE_NOT_INSTALLED,
    APP_STAGE_NO_DESKTOP,
    APP_STAGE_CONFIG_REFUSED,
    APP_STAGE_STATE_FAILED,
    APP_STAGE_SPAWN_FAILED,
    APP_STAGE_EXITED_EARLY,
    APP_STAGE_NOT_READY,
    APP_STAGE_UNSUPPORTED,
};

struct app_open_result {
    enum app_open_status status;
    enum app_open_stage stage;
    char id[APP_LAUNCH_ID_MAX + 1];
    long pid;
    int64_t ready_ms;
    const char *ready_basis;  /* "marker" or "alive" */
    const char *found_by;     /* already_open: "record" or "scan" */
    char executable[APP_LAUNCH_PATH_MAX];
    char sha256[65];
    char log_path[APP_LAUNCH_PATH_MAX];
    enum app_raise_outcome raise;
    char raise_note[160];
    bool exited;
    int exit_code;
    int term_signal;
    char log_tail[APP_LAUNCH_TAIL_MAX];
    char message[384];
    char hint[384];
};

/* The process's own environment: the running binary's directory, the
 * operator apps.tsv, ~/.local/state/z23/apps and the desktop session.
 * False (with why) when the state directory cannot be named. */
bool app_launch_env_from_process(struct app_launch_env *env, char *why,
                                 size_t why_size);

/* Built-in rows, then the operator file. An unsafe operator file is refused
 * whole (config_error); the built-in rows are still listed. */
void app_launch_registry_load(const struct app_launch_env *env,
                              struct app_launch_registry *reg);
/* Case-sensitive id or alias match; NULL when unknown. */
const struct app_launch_entry *
app_launch_registry_find(const struct app_launch_registry *reg,
                         const char *name);
/* "a, b, c" of every id; false when it does not fit. */
bool app_launch_known_names(const struct app_launch_registry *reg, char *out,
                            size_t out_size);

/* The verified running instance, or 0. Pid record first (alive, same
 * executable, same start time), then on Linux a /proc scan of this user's
 * processes for the same executable. */
long app_launch_running_pid(const struct app_launch_env *env,
                            const struct app_launch_entry *entry,
                            const char **found_by);

void app_launch_open(const struct app_launch_env *env,
                     const struct app_launch_registry *reg, const char *name,
                     struct app_open_result *out);

const char *app_open_stage_name(enum app_open_stage stage);
const char *app_open_status_name(enum app_open_status status);

/* ── process layer (native_app_launch_process.c) ─────────────────────── */

/* Executable path and kernel start time of a live, non-zombie process.
 * A path the kernel marks " (deleted)" is returned without that suffix. */
bool app_proc_identity(long pid, char exe[APP_LAUNCH_PATH_MAX],
                       uint64_t *start_time);
/* Lowest pid owned by this user whose executable is exe; 0 when none or
 * when the host has no process table to scan. */
long app_proc_scan(const char *exe);
/* SIGUSR1 to an app whose entry declares raise support. On Linux the
 * process must also show a SIGUSR1 handler in /proc SigCgt, so a build
 * without the handler is never ended by the signal; other POSIX hosts rely
 * on the declaration. Never called for an app that declares no raise.
 * note says what was done or why nothing was sent. */
enum app_raise_outcome app_proc_raise(long pid, char *note, size_t note_size);
const char *app_raise_outcome_name(enum app_raise_outcome raise);

struct app_spawn_outcome {
    long pid;
    int spawn_errno;
    bool exited;
    int exit_code;
    int term_signal;
    bool ready;
    int64_t ready_ms;
};
/* posix_spawn with no shell, a new session, stdin from /dev/null, stdout and
 * stderr to log_path (truncated), default signal dispositions, and no
 * inherited descriptor above 2; then wait for the ready marker (or settle). */
bool app_proc_spawn_and_wait(const struct app_launch_entry *entry,
                             const char *log_path, int timeout_ms,
                             int settle_ms, struct app_spawn_outcome *out);
/* The last lines of a log file, at most out_size - 1 bytes. */
void app_proc_log_tail(const char *path, char *out, size_t out_size);

/* ── pid record (native_app_launch_record.c) ─────────────────────────── */

struct app_launch_record {
    char id[APP_LAUNCH_ID_MAX + 1];
    long pid;
    uint64_t start_time;
    char executable[APP_LAUNCH_PATH_MAX];
};

/* Validated, written to a private sibling, fsynced, renamed over
 * <state_dir>/<id>.pid and the directory fsynced. */
bool app_launch_record_save(const char *state_dir,
                            const struct app_launch_record *rec);
/* False when absent or malformed. */
bool app_launch_record_load(const char *state_dir, const char *id,
                            struct app_launch_record *rec);
/* Create state_dir (and parents) owner-private; false with errno. */
bool app_launch_state_dir_ready(const char *state_dir);

#endif /* ZCL_TOOLS_NATIVE_APP_LAUNCH_H */
