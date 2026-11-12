/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * native_app_compose — how the front door's composite leaves (app.copy,
 * app.share, app.receive) and the CLI front door run other leaves: by
 * registry path, at run time, through the leaf's own input contract and
 * handler, exactly as zcode.package.bundle.receive runs zcode.package.fork.
 *
 * An inner call skips MCP policy. A composite that runs an owner leaf is
 * therefore AUTH_OWNER itself; that is the authority rule these helpers
 * rely on, never a check they make. */

#ifndef ZCL_TOOLS_NATIVE_APP_COMPOSE_H
#define ZCL_TOOLS_NATIVE_APP_COMPOSE_H

#include "command/native_command.h"
#include "json/json.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Checked receipt projection and bounded recovery-fact composition. */
bool zcl_app_recovery_fields(struct json_value *out, const struct json_value *source,
    const char *const *keys, size_t count);
bool zcl_app_optional_fields(struct json_value *out, const struct json_value *source,
    const char *const *keys, size_t count);
bool zcl_app_fact_add(struct json_value *facts, const char *key,
    const struct json_value *value, size_t cap);

/* Run leaf `path` on `input` into `out`, which this initializes (the
 * caller always frees it). False when the leaf is not registered (*absent
 * true when given), its input contract refuses the input (INPUT_REFUSED in
 * out) or the leaf does not pass. */
bool zcl_app_inner_call(const char *path, const struct json_value *input,
                        struct zcl_command_reply *out, bool *absent);

/* The plan call, then the same input plus the plan's plan_id and
 * confirm:true. `input` gains those two keys. */
bool zcl_app_inner_plan_confirm(const char *path, struct json_value *input,
                                struct zcl_command_reply *out);

/* A non-empty string of a reply's data, or NULL. */
const char *zcl_app_inner_str(const struct zcl_command_reply *r,
                              const char *key);

/* Bounded projection of an actual successful inner call. Every listed field
 * is required and must have the given JSON type; no unlisted data is copied. */
struct zcl_app_observation_field { const char *name; enum json_type type; };
bool zcl_app_observation(struct json_value *out, const char *command,
    const struct zcl_command_reply *reply,
    const struct zcl_app_observation_field *fields, size_t count, size_t max_bytes);
/* Refuse an oversized committed result while retaining bounded recovery facts. */
void zcl_app_bound_committed_result(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const char *command);
bool zcl_app_copy_recovery(struct json_value *out, const struct json_value *source);

/* Fail `reply` with the inner leaf's own refusal (code, message, evidence),
 * marking it mutated when the inner leaf did or `mutated` says an earlier
 * step already did. */
void zcl_app_inner_fail(struct zcl_command_reply *reply,
                        const struct zcl_command_reply *inner, bool mutated);

/* A fresh object input {kv[0]: kv[1], ...} of strings; NULL values are
 * left out. `in` is initialized even on false (allocation). */
bool zcl_app_input(struct json_value *in, const char *const *kv, size_t n);

/* zcl_app_inner_call when `built` (the input was made), else an ALLOC
 * refusal in `out`. `out` is always initialized and `in` always freed. */
bool zcl_app_inner_call_built(const char *path, struct json_value *in,
                              bool built, struct zcl_command_reply *out);

/* Copy the caller's integer `day` input, when present, into `in`. */
bool zcl_app_input_day(const struct json_value *from, struct json_value *in);

/* publisher_fingerprint (the full 66 hex) and publisher (the short form)
 * into `d`; nothing when `full` is NULL. */
void zcl_app_push_publisher(struct json_value *d, const char *full);

/* Render a front-door command hint that works when pasted:
 * "z23 [-datadir=DIR ]app " followed by trusted literal syntax and %s slots,
 * each slot holding one whole argument. No other printf conversions are
 * supported. Datadir and slots are POSIX-shell quoted; control bytes refuse.
 * The datadir part is present only when `datadir` is non-empty,
 * so pass the request's own datadir, or NULL for a command another person
 * runs in their own datadir. False, with out emptied, when it does not fit
 * in cap. */
[[gnu::format(printf, 4, 5)]]
bool zcl_app_hint(char *out, size_t cap, const char *datadir, const char *fmt,
                  ...);

/* Record the program path the user ran (argv[0]) so zcl_app_hint starts
 * every hint with it: "build/bin/z23 app ..." pastes from a fresh clone,
 * "z23 app ..." stays when z23 was found on PATH. NULL, empty, over-long or
 * unquotable input restores the plain "z23". */
void zcl_app_set_program(const char *argv0);

/* Same as zcl_app_hint but always starts with the plain "z23 ", never the
 * recorded program path: for a command another person runs on their own
 * machine, where the sender's path does not exist. */
[[gnu::format(printf, 4, 5)]]
bool zcl_app_hint_neutral(char *out, size_t cap, const char *datadir,
                          const char *fmt, ...);

/* SHA3-256(domain 0x00 || each part with its NUL): a composite plan_id
 * bound to the inner plans it will confirm. NULL parts hash as "". */
void zcl_app_plan_id(const char *domain, const char *const *parts,
                     size_t count, uint8_t out[32]);

#endif /* ZCL_TOOLS_NATIVE_APP_COMPOSE_H */
