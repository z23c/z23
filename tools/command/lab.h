/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: The one-file lab. Compile a single C23 translation unit with the
 * in-tree compiler cache, run it confined, and return ground truth.
 *
 * lab_build.c owns the toolchain, state directory, compile and confined run.
 * lab_receipt.c owns hashing, JSON receipts and the content-addressed store.
 * native_lab_command.c owns the lab.run / lab.test / lab.show leaves. */
#ifndef ZCL_TOOLS_COMMAND_LAB_H
#define ZCL_TOOLS_COMMAND_LAB_H

#include "command/lab_exec.h"
#include "json/json.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Receipt and cases files are opened without following links on every host
 * that has the flags; the confined run itself is Linux only. */
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

enum {
    LAB_SRC_MAX = 256 * 1024,
    LAB_STDIN_MAX = 64 * 1024,
    LAB_ARGS_MAX = 32,
    LAB_CASES_MAX = 256,
    LAB_TIMEOUT_DEFAULT_MS = 5000,
    LAB_TIMEOUT_MAX_MS = 60000,
    LAB_MEM_DEFAULT_MB = 256,
    LAB_MEM_MAX_MB = 2048,
    LAB_COMPILE_TIMEOUT_MS = 30000,
    LAB_DIAG_MAX = 64,
    LAB_DIAG_MESSAGE = 200,
    LAB_TAIL_MAX = 4096,
    LAB_PATH = 1024,
    LAB_ROOT_HEX = 128,
    LAB_FIRST_MAX = 1024,
    LAB_WORKDIR_MAX = 64 * 1024 * 1024,
};

struct lab_dirs {
    char base[LAB_PATH];
    char cc[LAB_PATH];
    char run[LAB_PATH];
    char receipts[LAB_PATH];
    char zcc[LAB_PATH];
};

struct lab_toolchain {
    char zcc[LAB_PATH]; /* empty when the compile cache is not installed */
    char cc[LAB_PATH];
    char identity[LAB_ROOT_HEX + 1]; /* SHA3-512 of compiler and cache stat */
};

enum lab_err {
    LAB_OK,
    LAB_E_BAD_FILE,    /* not a .c path, not a regular file, not owned */
    LAB_E_NOT_FOUND,
    LAB_E_TOO_LARGE,
    LAB_E_NO_COMPILER,
    LAB_E_STATE,       /* the lab state directory cannot be prepared */
    LAB_E_UNSUPPORTED, /* not a Linux host */
};

struct lab_source {
    char path[LAB_PATH];
    char base[72]; /* sanitized file name used inside the compile directory */
    uint8_t *bytes;
    size_t len;
};

struct lab_diag {
    int line;
    int col;
    char severity[8];
    char message[LAB_DIAG_MESSAGE + 1];
};

struct lab_compile {
    bool ok;
    bool sanitized;               /* the binary carries ASan and UBSan */
    bool sanitizers_unavailable;  /* requested, toolchain cannot provide them */
    int64_t wall_us;
    size_t n_diag;
    struct lab_diag diag[LAB_DIAG_MAX];
    char tail[LAB_TAIL_MAX + 1];
    char binary[LAB_PATH];
    char detail[160];             /* non-empty when the compile did not start */
    bool unconfined;              /* confinement refused the compile child */
};

struct lab_inputs {
    const char *stdin_data;
    size_t stdin_len;
    const char *const *args;
    size_t n_args;
    bool sanitize;
    uint32_t timeout_ms;
    uint32_t mem_mb;
};

/* State directory: $Z23_LAB_DIR, else $HOME/.z23/lab. Creates the layout. */
enum lab_err lab_dirs_open(struct lab_dirs *dirs);
enum lab_err lab_toolchain_find(struct lab_toolchain *tc);

/* Read a source file: a .c path naming a regular file this user owns,
 * at most LAB_SRC_MAX bytes. */
enum lab_err lab_source_load(const char *path, struct lab_source *src);
void lab_source_free(struct lab_source *src);

/* Compile with -std=c23 -O1 -g -Wall -Wextra -Werror -pedantic, libc and libm
 * only. `name` is the content-address prefix naming the compile directory. */
void lab_compile_source(const struct lab_dirs *dirs,
                        const struct lab_toolchain *tc,
                        const struct lab_source *src, const char *name,
                        bool sanitize, struct lab_compile *out);
void lab_compile_cleanup(const struct lab_dirs *dirs, const char *name);

/* Run a compiled binary once in a fresh private workdir. */
void lab_run_binary(const struct lab_dirs *dirs, const char *binary,
                    bool sanitized, const struct lab_inputs *in,
                    struct lab_proc *out);

/* Count findings in sanitizer output and copy the first (at most cap-1 bytes). */
size_t lab_scan_sanitizer(const char *text, size_t len, char *first, size_t cap);

/* Counters for tests: compiles and runs actually performed by this process. */
size_t lab_compile_count(void);
size_t lab_run_count(void);

/* Hex SHA3-512 over length-prefixed fields (see lab_receipt.c). */
struct lab_hasher;
struct lab_hasher *lab_hasher_new(const char *kind);
void lab_hasher_field(struct lab_hasher *h, const char *tag, const void *data,
                      size_t len);
void lab_hasher_u64(struct lab_hasher *h, const char *tag, uint64_t v);
void lab_hasher_finish(struct lab_hasher *h, char hex[LAB_ROOT_HEX + 1]);

/* Receipt store: <state>/receipts/<root>.json. */
bool lab_root_valid(const char *root);
bool lab_receipt_store(const struct lab_dirs *dirs, const char *root,
                       const struct json_value *receipt);
bool lab_receipt_load(const struct lab_dirs *dirs, const char *root,
                      struct json_value *receipt);

/* Presentation: copy a capture as lossy UTF-8 into a JSON string within
 * `escaped_cap` serialized bytes. `*cut` is set when text was dropped. */
bool lab_json_text(struct json_value *obj, const char *key, const char *text,
                   size_t len, size_t escaped_cap, bool *cut);

/* Receipt sections. */
bool lab_json_compile(struct json_value *out, const struct lab_compile *c);
bool lab_json_run(struct json_value *out, const struct lab_proc *p, bool ran,
                  bool *cut_out);
bool lab_json_sanitizer(struct json_value *out, const struct lab_compile *c,
                        bool requested, size_t findings, const char *first);
bool lab_json_confinement(struct json_value *out, bool applied, bool pidns);

#endif
