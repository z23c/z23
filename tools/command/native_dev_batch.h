/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the helpers dev.batch.requeue, dev.batch.restack and
 *          dev.batch.slim share (native_dev_batch_ledger.c): the lab state
 *          directory the shell bridges also use, its tick lock, the
 *          byte-compatible TSV ledgers, and a no-shell git call. SHADOW
 *          STEP: these leaves compute the decision the bridges
 *          (requeue.sh, restack-failed.sh, slim-stacks.sh) make; the
 *          bridges keep acting. Nothing outside the three leaves and
 *          their tests includes this header. */

#ifndef ZCL_NATIVE_DEV_BATCH_H
#define ZCL_NATIVE_DEV_BATCH_H

#include <stdbool.h>
#include <stddef.h>

#include "command/native_command.h"

#define DB_PATH 4096u
/* The largest ledger, outcome or log file one leaf reads whole. */
#define DB_FILE_CAP (64u * 1024u * 1024u)
#define DB_GIT_TIMEOUT_MS (2 * 60 * 1000)

/* Every location is derived from `home` (--home, default $HOME) except the
 * state directory (--state-dir, default <home>/development/z23/handoff/
 * handoff-20261025), so a test points one option at a temp tree. */
struct db_paths {
    char home[DB_PATH];
    char state[DB_PATH];
    char ledger[DB_PATH + 32];    /* stacked.tsv */
    char pending[DB_PATH + 32];   /* stack-pending.txt */
    char restacked[DB_PATH + 32]; /* restacked.tsv */
    char lock[DB_PATH + 32];      /* .stack-tick.lock */
};

/* A whole file held in memory; a missing file is an empty text. */
struct db_text {
    char *p;
    size_t n;
};

/* The string option `key` (the underscore spelling, or the hyphen spelling a
 * CLI flag may carry), or "" when absent. */
const char *db_opt_str(const struct json_value *in, const char *key);
bool db_opt_flag(const struct json_value *in, const char *key);

void db_refuse(struct zcl_command_reply *reply, const char *code,
               const char *phase, const char *message);
bool db_join(char *out, size_t cap, const char *a, const char *b);
/* Fills the paths from the options; refuses (reply set) when one is too long. */
bool db_paths_init(const struct json_value *in, struct db_paths *p,
                   struct zcl_command_reply *reply);

/* flock(2) exclusive on `path`, the same lock flock(1) takes in the shell
 * bridges. -1 when it cannot be opened or taken. */
int db_lock(const char *path);
void db_unlock(int fd);

bool db_text_load(const char *path, struct db_text *t);
void db_text_free(struct db_text *t);
/* Write-then-rename in the same directory, as the bridges' ".new" + mv. */
bool db_text_save(const char *path, const char *data, size_t n);
bool db_append(const char *path, const char *data, size_t n);

/* Line iteration over a text: false at the end. `line` is not terminated. */
bool db_next_line(const struct db_text *t, size_t *pos, const char **line,
                  size_t *len);
/* True when tab-separated field `idx` of the line equals `key` exactly. */
bool db_field_is(const char *line, size_t len, size_t idx, const char *key);
bool db_has_first_field(const struct db_text *t, const char *key);
bool db_field_copy(const char *line, size_t len, size_t idx, char *out,
                   size_t cap);

/* git -C dir ARGS..., stdout (stderr dropped) into out; the exit status. */
int db_git(const char *dir, const char *const *args, char *out, size_t cap);
/* One git line, trailing newline stripped; false on a non-zero exit. */
bool db_git_line(const char *dir, const char *const *args, char *out,
                 size_t cap);

/* Append {s} to a JSON array value. */
void db_push_str(struct json_value *arr, const char *s);

/* requeue's primitive, reused by restack's tests: drop every stacked.tsv row
 * whose first field is `lane`; *dropped counts them. */
bool db_ledger_drop_lane(const char *path, const char *lane, size_t *dropped);

#endif
