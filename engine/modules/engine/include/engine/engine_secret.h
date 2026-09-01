/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine_secret — hold one API key, and make it structurally hard to emit.
 *
 * ── REDACTION BY CONSTRUCTION, NOT BY REMEMBERING ────────────────────────
 * A rule that says "do not log the key" is a rule somebody forgets on the
 * day they add a debug line. So the key is not a string the harness passes
 * around. It is loaded into this module, and the ONLY way out of it is
 * engine_secret_authorization_header(), which is called by exactly one
 * function — the TLS request builder — and whose result is never stored.
 *
 * Everything the harness writes to a terminal, a transcript, or a receipt
 * goes through engine_emit_*() below, which scrubs before it writes. There is
 * no "please redact this" call for a caller to skip: the redacting writer is
 * the only writer.
 *
 * The scrub removes two things:
 *   1. the loaded key itself, if one is loaded;
 *   2. anything key-SHAPED, whether or not it is the loaded key — an
 *      `Authorization: Bearer ...` value, an `sk-`/`xai-`/`gsk_` token, or a
 *      long `<hex>.<alnum>` pair. That second class matters because the thing
 *      most likely to end up in a transcript is a key this process never
 *      loaded: one the MODEL echoed back, one in an error message from the
 *      vendor, or one in a file the unit was asked to read.
 *
 * ── WHERE A KEY MAY LIVE ────────────────────────────────────────────────
 * An environment variable, or a file outside the repository with mode 0600.
 * A file with any other mode is REFUSED, not warned about: a world-readable
 * key on a shared box is already spent. There is no in-repo key path and no
 * flag that creates one.
 */

#ifndef ZCL_ENGINE_SECRET_H
#define ZCL_ENGINE_SECRET_H

#include "engine/engine.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#define ENGINE_SECRET_MAX 512

/* Load the vendor's key. `explicit_path`, when non-NULL, overrides both the
 * environment variable and the vendor's default file. A fixture vendor needs
 * no key and loading one for it succeeds trivially.
 *
 * Returns false when no key could be found or when the file that holds it is
 * not mode 0600. `where` receives a description of the SOURCE — "the
 * ZAI_API_KEY environment variable", never any part of the value. */
bool engine_secret_load(const struct engine_vendor *v, const char *explicit_path,
                        char *where, size_t where_len);

/* True once a key is held. */
bool engine_secret_loaded(void);

/* Build `Authorization: Bearer <key>` into the caller's buffer. The single
 * legitimate exit for the key, called from the transport and nowhere else.
 * The buffer must be wiped by the caller; the transport does. */
bool engine_secret_authorization_header(char *out, size_t out_len);

/* Wipe the held key. Called on every exit path. */
void engine_secret_clear(void);

/* ── the only writers ────────────────────────────────────────────────── */

/* Scrub in place. Exported so tests/harness/src/test_engine.c can assert on the
 * scrubber directly; the harness itself uses the emitters below. */
void engine_redact_inplace(char *s);

/* printf to `f`, scrubbing the formatted text first. */
void engine_emit(FILE *f, const char *fmt, ...);

/* Write `text` to `path` (mode 0600), scrubbing first. Used for transcripts,
 * gate logs, and receipts — every durable artifact this harness leaves. */
bool engine_emit_file(const char *path, const char *text, size_t len);

#endif /* ZCL_ENGINE_SECRET_H */
