/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations for the check-zcc-epoch-object gate port
 * (gate_zcc_epoch_object*.c). Split across util / part1 / late / refuse
 * translation units so every file stays under the 800-line house bound.
 * No heap: every path lives in a fixed ZEO_PATH buffer.
 */
#ifndef GATE_ZCC_EPOCH_OBJECT_PRIV_H
#define GATE_ZCC_EPOCH_OBJECT_PRIV_H

#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

enum { ZEO_PATH = 2048, ZEO_TEXT = 4096, ZEO_HASH = 65, ZEO_STAMP = 128 };

struct zeo {
    char root[ZEO_PATH];
    char zcc[ZEO_PATH];
    char zcc_copy[ZEO_PATH];
    char work[ZEO_PATH];
    char source[ZEO_PATH];
    char seed[ZEO_PATH];
    char source_id[ZEO_HASH];
    char mutation[ZEO_HASH];
    char epoch[ZEO_HASH];
    char compiler_id[ZEO_HASH];
    char object_base[ZEO_PATH];
    char object_root[ZEO_PATH];
    char admission_lock[ZEO_PATH];
    char session[ZEO_PATH];
    char unverified[ZEO_PATH];
    char expected[ZEO_PATH];
    char object[ZEO_PATH];
    char zcc_log[ZEO_PATH];
    char compiler_launches[ZEO_PATH];
    char lock_compile_done[ZEO_PATH];
    char refusal_marker[ZEO_PATH];
    char refusal[ZEO_PATH];
    char counting[ZEO_PATH];
    char make_copy[ZEO_PATH];
    char marker_stamp[ZEO_STAMP];
    char posix_cc[32];
    pid_t lock_holder;
    pid_t locked_compile;
};

void zeo_set_ctx(struct zeo *z);
[[noreturn]] void zeo_fail(const char *msg);
[[noreturn]] void zeo_failf(const char *fmt, ...);
[[noreturn]] void zeo_bail(int code);
void zeo_cleanup(struct zeo *z);

int zeo_join(char *dst, size_t cap, const char *a, const char *b);
int zeo_dep_of(char *dst, size_t cap, const char *obj);
int zeo_gcno_of(char *dst, size_t cap, const char *obj);
int zeo_sha256_hex(const char *s, char out[ZEO_HASH]);

int zeo_write_file(const char *path, const char *text);
int zeo_append_raw(const char *path, const char *data, size_t n);
int zeo_append_file(const char *path, const char *text);
int zeo_copy_file(const char *src, const char *dst);
int zeo_files_equal(const char *a, const char *b);
int zeo_read_file(const char *path, char *buf, size_t cap, size_t *len);
int zeo_read_first(const char *path, char *buf, size_t cap);
int zeo_exists(const char *path);
long zeo_size(const char *path);
int zeo_nonempty(const char *path);
int zeo_file_stamp(const char *path, char *out, size_t cap);

long zeo_count_lines(const char *path);
long zeo_count_line_eq(const char *path, const char *token);
long zeo_count_first_field(const char *path, const char *word);
long zeo_outcome_count(const char *path);
int zeo_tail1(const char *path, char *out, size_t cap);
int zeo_first_tok_is(const char *line, const char *word);
int zeo_grep_f(const char *needle, const char *path);
int zeo_grep_re(const char *pattern, const char *path);
int zeo_head_to_stderr(const char *path, long lines);

pid_t zeo_spawn(const char *path, char *argv[], const char *outf,
                const char *errf);
int zeo_wait(pid_t pid);
int zeo_run(const char *path, char *argv[], const char *outf,
            const char *errf);
int zeo_capture(const char *path, char *argv[], char *out, size_t cap);
int zeo_alive(pid_t pid);
int zeo_wait_file(const char *path, pid_t pid);
void zeo_wait_marker(const char *path, pid_t pid, const char *what);
int zeo_wait_lock_waiter(const char *lock, pid_t pid);

int zeo_dir_has_file(const char *dir);
int zeo_dir_has_entry_prefix(const char *dir, const char *prefix);
int zeo_dir_link(const char *link, const char *target);
int zeo_dir_unlink(const char *link);
int zeo_is_windows(void);
int zeo_which(const char *name, char *out, size_t cap);

void zeo_expect_log_output(struct zeo *z, const char *suffix);
int zeo_compile_x(struct zeo *z, const char *zccpath, const char *mode,
                  const char *output, char *const args[], const char *outf,
                  const char *errf, pid_t *bg, int *rc);
int zeo_legacy_x(struct zeo *z, const char *mode, const char *output,
                 char *const args[], const char *outf, const char *errf,
                 pid_t *bg, int *rc);
int zeo_backend_x(struct zeo *z, int native, const char *mode,
                  const char *output, char *const args[], const char *outf,
                  const char *errf, pid_t *bg, int *rc);

void zeo_write_session(const struct zeo *z);
void zeo_write_marker(const struct zeo *z, const char *path, char *text,
                      size_t cap, const char *fmt, const char *ovf_msg,
                      const char *write_msg);
void zeo_args_wrap(char *args[10], const char *wrapper, const char *counting,
                   const char *dflag, const char *seed);

int zeo_part1(struct zeo *z);
int zeo_part2(struct zeo *z);
int zeo_part3(struct zeo *z);

#endif
