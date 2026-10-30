/* Copyright 2026 Rhett Creeton - Apache License 2.0
 *
 * Shared declarations for the check_ship_remote_transaction gate port
 * (gate_ship_remote_transaction.c + gate_ship_remote_transaction_util.c).
 * The selftest (gate_ship_remote_transaction_selftest.c) also uses these
 * helpers. No heap anywhere: fixed buffers, ovf-checked snprintf.
 */
#ifndef GATE_SHIP_REMOTE_TRANSACTION_PRIV_H
#define GATE_SHIP_REMOTE_TRANSACTION_PRIV_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stddef.h>
#include <stdio.h>

enum { SRT_PATH = 1024, SRT_SHA = 65, SRT_TEXT = 8192, SRT_OUT = 65536,
       SRT_LINEBUF = 4096 };

static const char k_srt_gate[] = "check_ship_remote_transaction";

typedef int (*srt_line_fn)(void *ctx, const char *line, size_t len);

int srt_run(char *const *argv, const char *home, const char *path_pre,
            const char *out_path, int merge_err, int *rc);
int srt_ps_comm(long pid, char *out, size_t cap);
int srt_sha256_file(const char *path, char out[SRT_SHA]);
int srt_live_exe_sha(long pid, char out[SRT_SHA]);
int srt_read_file(const char *path, char *buf, size_t cap, size_t *len);
int srt_write_file(const char *path, const char *text);
int srt_write_exec(const char *path, const char *text);
int srt_copy_file(const char *src, const char *dst, int exec_bit);
int srt_append_file(const char *dst, const char *src);
int srt_each_line(const char *path, srt_line_fn fn, void *ctx);
int srt_file_has_exact_line(const char *path, const char *line);
int srt_file_contains(const char *path, const char *needle);
int srt_grep_lineno(const char *path, const char *needle, int prefix,
                    int last, long *lineno);
int srt_mkdirp(const char *path);
int srt_read_pid(const char *pidfile, long *pid);
size_t srt_count_lines(const char *buf, size_t len);
const char *srt_tmpdir(void);


struct srt_ctx {
    char tmp[SRT_PATH], old[SRT_PATH], new[SRT_PATH];
    char home[SRT_PATH], release[SRT_PATH], incoming[SRT_PATH];
    char manifest[SRT_PATH], state_file[SRT_PATH], pidfile[SRT_PATH];
    char mockbin[SRT_PATH], dropin[SRT_PATH], dropin_dir[SRT_PATH];
    char binding_check[SRT_PATH], release_check[SRT_PATH];
    char activate[SRT_PATH], rollback[SRT_PATH];
    char node_unit[128];
    char old_sha[SRT_SHA], new_sha[SRT_SHA], manifest_sha[SRT_SHA];
    char source_id[SRT_SHA];
};

int srt_fixture_state_pub(struct srt_ctx *c, const char *f1, const char *f2,
                          const char *f3);
int srt_invoke_activate(struct srt_ctx *c, const char *fault, const char *out,
                        int merge, int *rc);
int srt_invoke_binding_pub(struct srt_ctx *c, const char *fault,
                           const char *out, int merge, int *rc);
int srt_reset(struct srt_ctx *c);
int srt_assert_old_selected(struct srt_ctx *c);
int srt_check_all(struct srt_ctx *c);

#endif
