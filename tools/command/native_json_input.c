/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shared bounded stdin reads and native JSON error envelopes. */
#include "command/native_json_input.h"
#include "json/json.h"
#include "util/safe_alloc.h"
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

static bool native_input_grow(char **buffer, size_t *capacity, size_t hard_cap)
{
    size_t next = *capacity > hard_cap / 2u ? hard_cap : *capacity * 2u;
    char *grown = zcl_realloc(*buffer, next, "native_command.stdin");
    if (!grown) return false;
    *buffer = grown;
    *capacity = next;
    return true;
}

static ssize_t native_input_read(void *buffer, size_t length)
{
    ssize_t count;
    do { count = read(STDIN_FILENO, buffer, length); }
    while (count < 0 && errno == EINTR);
    return count;
}

char *zcl_native_read_stdin(size_t max_bytes, bool *oversize, size_t *length)
{
    size_t ignored_length;
    bool ignored_oversize;
    if (!length) length = &ignored_length;
    if (!oversize) oversize = &ignored_oversize;
    *length = 0;
    *oversize = false;
    if (max_bytes > SIZE_MAX - 2u) return NULL;
    if (max_bytes < 2)
        max_bytes = 2;
    /* One byte past the budget so an OVER-limit document is detected by
     * actually reading the extra byte, never inferred from a full buffer —
     * a document of exactly max_bytes must be accepted, not refused. */
    const size_t hard_cap = max_bytes + 2; /* +1 sentinel, +1 NUL */
    size_t cap = 4096, len = 0;
    if (cap > hard_cap)
        cap = hard_cap;
    char *buf = (char *)zcl_malloc(cap, "native_command.stdin");
    if (!buf)
        return NULL;
    for (;;) {
        if (len + 1 >= cap) {
            if (cap >= hard_cap)
                break; /* read the sentinel byte; length check below rules */
            if (!native_input_grow(&buf, &cap, hard_cap)) {
                free(buf);
                return NULL;
            }
        }
        ssize_t r = native_input_read(buf + len, cap - len - 1);
        if (r < 0) {
            free(buf);
            return NULL;
        }
        if (r == 0)
            break;
        len += (size_t)r;
    }
    if (len > max_bytes) {
        *oversize = true;
        free(buf);
        return NULL;
    }
    buf[len] = 0;
    *length = len;
    return buf;
}

static void nc_print_error_build_error(const char *code, const char *phase,
                                       const char *message,
                                       const char *evidence,
                                       const char *next_reason,
                                       bool has_next,
                                       struct json_value *error)
{
    struct json_value blockers;
    json_init(&blockers);
    json_set_array(&blockers);
    (void)json_push_kv_str(error, "code", code);
    (void)json_push_kv_str(error, "error_code", code);
    (void)json_push_kv_str(error, "message", message);
    (void)json_push_kv_str(error, "phase", phase);
    (void)json_push_kv_str(error, "current_state", "REQUEST_FAILED");
    (void)json_push_kv_bool(error, "retryable", false);
    (void)json_push_kv_bool(error, "human_action_required", true);
    (void)json_push_kv_str(error, "next_action",
                           next_reason && next_reason[0]
                               ? next_reason
                               : has_next ? "follow the first next command"
                                          : "inspect the command contract");
    (void)json_push_kv_bool(error, "mutated", false);
    if (evidence && evidence[0])
        (void)json_push_kv_str(error, "evidence", evidence);
    (void)json_push_kv(error, "blockers", &blockers);
    json_free(&blockers);
}

size_t zcl_native_error_json(const char *command, const char *code,
    const char *phase, const char *message, const char *evidence,
    const char *next_reason, const struct json_value *next, char *out, size_t cap)
{
    struct json_value root = {0}, error = {0}, empty = {0};
    json_set_object(&root); json_set_object(&error); json_set_array(&empty);
    if (!next) next = &empty;
    bool ok = json_push_kv_str(&root, "schema", "zcl.result.v1") &&
        json_push_kv_str(&root, "command", command ? command : "") &&
        json_push_kv_bool(&root, "ok", false) &&
        json_push_kv_str(&root, "status", "failed") &&
        json_push_kv_str(&root, "request_id", "local-cli") &&
        json_push_kv_int(&root, "elapsed_us", 0);
    nc_print_error_build_error(code, phase, message, evidence, next_reason,
                               next->num_children > 0, &error);
    ok = ok && json_push_kv(&root, "error", &error) && json_push_kv(&root, "next", next);
    size_t length = ok ? json_write(&root, out, cap) : 0;
    json_free(&empty); json_free(&error); json_free(&root);
    return length < cap ? length : 0;
}
