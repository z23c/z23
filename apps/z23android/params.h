/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_PARAMS_H
#define ZAPP_PARAMS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The Sapling proving parameters a shielded send needs. They ship inside the package as uncompressed
 * assets and are copied once to <files>/params, where the node finds them through -paramsdir. */
#define ZAPP_PARAMS_COUNT 2
#define ZAPP_PARAMS_DIR "params"
#define ZAPP_THERMAL_SEVERE 3 /* android/thermal.h: the lowest status at which proving is refused. */

struct zapp_param_file {
    const char *name;
    uint64_t size;
    const char *sha256; /* lowercase hex, 64 characters */
};
extern const struct zapp_param_file zapp_param_files[ZAPP_PARAMS_COUNT];

/* Where the copied parameters live: <files>/params. False when the path does not fit. */
bool zapp_params_path(const char *files, char *out, size_t cap);

/* True when <files>/params holds every file as a regular file of the pinned size. This is a cheap
 * look for the UI and for choosing node arguments. It does not read the bytes, so it never permits
 * a send: only a completed zapp_params_install or a true zapp_params_verify does. */
bool zapp_params_present(const char *files);

/* "-paramsdir=<files>/params" when the files are present; false and out untouched otherwise. The
 * node checks its own SHA-512 pin of each file when it loads them. */
bool zapp_params_arg(const char *files, char *out, size_t cap);

/* Reads every file under <files>/params and compares its length and SHA-256 with the pin. Reads
 * about 51.6 MB, so callers run it off the UI thread. */
bool zapp_params_verify(const char *files);

/* What the running node reports about proving. Unknown covers an unreachable node and a node that
 * does not report the status. */
enum zapp_proving {
    ZAPP_PROVING_UNKNOWN,
    ZAPP_PROVING_UNAVAILABLE, /* the node says it cannot prove a shielded spend */
    ZAPP_PROVING_ARMED        /* the node says it can: its own pin accepted the parameters */
};

/* Asks the node for its proving status. The integration implements it with one RPC to the running
 * node; tests supply a stub. Called on the thread that asks whether a send may start. */
struct zapp_proving_probe {
    void *ctx;
    enum zapp_proving (*status)(void *ctx);
};

/* Whether a shielded send may start. Refused, with a plain reason in why, unless the copy was
 * verified (params_verified: the install or verify of this process returned success), the node
 * reports ZAPP_PROVING_ARMED, and the thermal status (Android 0 none to 6 shutdown) is below
 * SEVERE. A negative thermal status means the platform has not reported one and does not refuse.
 * The check is a refusal before a send; it does not pause or delay a copy. */
bool zapp_prover_allowed(int thermal_status, bool params_verified, const struct zapp_proving_probe *node,
                         char *why, size_t cap);

/* Where the packaged bytes of one file come from. open returns a descriptor positioned anywhere,
 * with the file's bytes at [*offset, *offset + *length), or -1 when it is not there. The caller
 * closes the descriptor. */
struct zapp_params_source {
    void *ctx;
    int (*open)(void *ctx, const char *name, uint64_t *offset, uint64_t *length);
};

enum zapp_params_result {
    ZAPP_PARAMS_OK,
    ZAPP_PARAMS_MISSING, /* a packaged file is absent */
    ZAPP_PARAMS_SIZE,    /* a packaged file has the wrong length */
    ZAPP_PARAMS_HASH,    /* a copy does not match its pinned SHA-256 */
    ZAPP_PARAMS_IO       /* the private directory could not be written */
};

/* Makes <files>/params hold verified copies. Existing files are read and checked against the pinned
 * SHA-256 first; when they all match nothing is written and the source is not opened. Anything else,
 * a same-size corrupt copy included, is discarded and replaced from the source. Each file is written
 * to a private temporary directory, flushed, read back and checked before the directory is renamed
 * into place and the parent flushed. OK means every file under <files>/params matched its pin when
 * this call finished. On any other result, except unusable arguments (nothing is touched), no pinned
 * file remains under <files>/params, so zapp_params_present and zapp_params_verify are false: the
 * call removes what it wrote, including a directory it had already renamed when the final flush
 * failed. The directory itself stays only when it holds a file this code did not create. Blocking;
 * callers run it off the UI thread. why receives a plain sentence for the owner. */
enum zapp_params_result zapp_params_install(const struct zapp_params_source *source, const char *files,
                                            char *why, size_t cap);

/* The same with an explicit file table, for tests with small fixtures. */
enum zapp_params_result zapp_params_install_set(const struct zapp_param_file *set, size_t count,
                                                const struct zapp_params_source *source,
                                                const char *files, char *why, size_t cap);
bool zapp_params_present_set(const struct zapp_param_file *set, size_t count, const char *files);
bool zapp_params_verify_set(const struct zapp_param_file *set, size_t count, const char *files);
#endif
