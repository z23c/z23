/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * gate_receipt - declarations shared by the gate receipt wrapper
 * (gate_receipt.c), its process and signal layer (gate_receipt_proc.c) and
 * its text, digest and path helpers (gate_receipt_text.c).
 */
#ifndef ZCL_GATE_RECEIPT_H
#define ZCL_GATE_RECEIPT_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#include "crypto/sha3.h"

constexpr int GTR_EXIT_USAGE = 2;

/* Growable NUL-terminated byte string. */
struct gtr_buf {
    char *p;
    size_t len;
    size_t cap;
};

/* A read-only mapping of a whole file; an empty file maps to nothing. */
struct gtr_map {
    const char *p;
    size_t len;
};

typedef void (*gtr_sink_fn)(void *ctx, const char *p, size_t n);

enum gtr_err { GTR_ERR_INHERIT, GTR_ERR_NULL, GTR_ERR_MERGE };

/* One child: argv (execvp), optional stdin descriptor, whether stdout is
 * captured through a pipe into `sink`, and where stderr goes. */
struct gtr_job {
    char *const *argv;
    int in_fd;
    bool capture;
    bool out_to_err;
    enum gtr_err err;
    gtr_sink_fn sink;
    void *ctx;
};

/* gate_receipt_proc.c */
[[noreturn]] void gtr_die(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
[[noreturn]] void gtr_fail(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void gtr_cleanup(void);
void gtr_track_file(size_t slot, const char *path);
void gtr_untrack_file(size_t slot);
void gtr_track_dir(const char *path);
void gtr_signals_init(void);
void gtr_poll(void);
void gtr_nap(long ms);
int gtr_run(const struct gtr_job *job);
int gtr_write_all(int fd, const char *p, size_t n);
int gtr_mirror(int fd, const char *p, size_t n);

/* gate_receipt_text.c */
void *gtr_grow(void *p, size_t n);
void gtr_buf_add(struct gtr_buf *b, const void *p, size_t n);
const char *gtr_buf_str(struct gtr_buf *b);
void gtr_buf_addf(struct gtr_buf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void gtr_buf_chomp(struct gtr_buf *b);
char *gtr_fmt(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void gtr_sha3_buf(const void *p, size_t n, char hex[65]);
void gtr_sha3_sink(void *ctx, const char *p, size_t n);
void gtr_sha3_done(struct sha3_256_ctx *ctx, char hex[65]);
int gtr_map_open(const char *path, struct gtr_map *m);
void gtr_map_close(struct gtr_map *m);
void gtr_quote_word(struct gtr_buf *b, const char *s);
bool gtr_is_digits(const char *s);
bool gtr_slug_ok(const char *s);
bool gtr_token_present(const struct gtr_map *m, const char *token);
size_t gtr_count_newlines(const struct gtr_map *m);
int gtr_mkdir_p(const char *path);
char *gtr_logical_path(const char *dir);

#endif
