/* Copyright 2026 Rhett Creighton - Licensed under Apache-2.0
 *
 * purpose: Private interface between gate_object_reproducible.c (the gate:
 * cases, compile and link drivers, entry points) and
 * gate_object_reproducible_support.c (SHA-256, bounded file helpers, the ELF
 * section walk and the pure self-test). Nothing else includes it. Split out
 * only to keep each file under the 1500-line ceiling.
 */
#ifndef Z23_LINTC_GATE_OBJECT_REPRODUCIBLE_PRIV_H
#define Z23_LINTC_GATE_OBJECT_REPRODUCIBLE_PRIV_H

#include <stdbool.h>
#include <stddef.h>
#include <signal.h>
#include <stdint.h>

enum {
    OR_PATH = 1024,
    OR_MAXTOK = 512,
    OR_OBJ_MAX = 32 * 1024 * 1024,
    OR_DIAG = 256 * 1024,
    OR_DIAG_LINES = 8,
    OR_TIMEOUT_MS = 120000,
    OR_DEADLINE_S = 900, /* process-wide: the whole gate run */
    OR_DEPTH_MAX = 8,
    OR_RM_DEPTH = 24,
    OR_NAME = 80,
    OR_OK = 0,
    OR_MISMATCH = 1, /* the only result a report-only case may excuse */
    OR_REFUSED = 2,
};

struct or_cfg {
    const char *tree;
    const char *repro;
    const char *base;
    const char *shipped;
    const char *link;
    const char *libs;
    const char *cross;
    const char *targets;
    const char *strip;
    const char *seed;
    const char *allow;
    const char *report;
    const char *host_cc;
    const char *unsupported;
    bool seed_none;
};

struct or_case {
    const char *name;
    const char *cc;      /* NULL: the --host-cc value */
    bool cross;          /* freestanding units, --cross-flags, a --targets entry */
    bool shipped;        /* use the node object flags verbatim, one unit */
    bool link;           /* link a small program, hash it */
};

struct or_sha {
    uint32_t h[8];
    uint8_t blk[64];
    uint64_t total;
    size_t fill;
};

struct or_cmd {
    char tok[OR_MAXTOK][OR_PATH];
    const char *argv[OR_MAXTOK + 1];
    int n;
};

/* support.c: hashing, bounded files, ELF */
void or_sha_init(struct or_sha *s);
void or_sha_update(struct or_sha *s, const void *data, size_t len);
void or_sha_hex(struct or_sha *s, char out[65]);
void or_sha_buf(const void *data, size_t len, char out[65]);
unsigned char *or_read_file(const char *path, size_t *len);
bool or_hash_file(const char *path, char out[65]);
bool or_copy_file(const char *src, const char *dst);
bool or_mkparent(const char *path);
bool or_join(char *out, size_t cap, const char *a, const char *b);
bool or_copy_tree(const char *src, const char *dst, int depth);
bool or_rm_rf(const char *path, int depth);
bool or_find_exe(const char *name, char *out, size_t cap);
bool or_elf_valid(const unsigned char *b, size_t len);
bool or_elf_linked(const unsigned char *b, size_t len);
void or_elf_first_diff(const unsigned char *a, size_t la,
                       const unsigned char *b, size_t lb, char *out,
                       size_t cap);

/* gate.c: pieces the pure self-test drives */
extern volatile sig_atomic_t g_or_sig;
extern int64_t g_or_deadline_ms;
int64_t or_now_ms(void);
bool or_add(struct or_cmd *c, const char *s);
bool or_seal(struct or_cmd *c, bool ok);
bool or_parse(int argc, char **argv, struct or_cfg *cfg);
const char *or_cfg_flaw(const struct or_cfg *cfg);
int or_excuse(const struct or_cfg *cfg, const struct or_case *cs, int rc);
bool or_target_of(const char *list, const char *name, char *out, size_t cap);
bool or_contains(const unsigned char *h, size_t hl, const char *needle);
unsigned char *or_compile_run(const struct or_cmd *c, char *diag, size_t *len,
                              const char **why);

#endif
