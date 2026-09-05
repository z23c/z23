/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The record shape, the chain rule, and why this file is not the binary
 * chainlog are all in engine/engine_receipt.h. Read that first.
 *
 * This file is the one place in engine/modules/engine that touches a file
 * descriptor. Everything else in the module is a pure function of its
 * arguments, and that property is worth naming rather than losing quietly:
 * the append here opens one path the caller named, reads its tail, and
 * appends one line. It resolves no path of its own, follows no environment
 * variable, and writes nothing anywhere else.
 */

#include "engine/engine_receipt.h"
#include "engine/engine.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "json/json.h"
#include "sha3/sha3.h"
#if defined(_WIN32)
#include "platform/windows_path.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <io.h>
#include <windows.h>
#endif

/* POSIX descriptors use close-on-exec. Windows uses _O_NOINHERIT and binary
 * mode in receipt_open(), because text translation would change hashed bytes. */
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static int receipt_open(const char *path, int flags, int mode)
{
#if defined(_WIN32)
    wchar_t wide[32768];
    if (!platform_windows_wide_path(path, wide)) {
        errno = EINVAL;
        return -1;
    }
    return _wopen(wide, flags | _O_BINARY | _O_NOINHERIT, mode);
#else
    return open(path, flags | O_CLOEXEC, mode);
#endif
}

static const char *or_empty(const char *s)
{
    return s ? s : "";
}

static bool push_nullable_string(struct json_value *doc, const char *key,
                                 const char *value)
{
    if (value && value[0])
        return json_push_kv_str(doc, key, value);
    struct json_value null_value;
    json_init(&null_value);
    json_set_null(&null_value);
    bool ok = json_push_kv(doc, key, &null_value);
    json_free(&null_value);
    return ok;
}

static void sha3_hex(const char *data, size_t len, char out[65])
{
    uint8_t digest[32];
    zcl_sha3_256((const unsigned char *)data, len, digest);
    zcl_hex_encode(digest, 32, out);
    out[64] = '\0';
}

/* A whole-file lock covers the tail-read and single append write, so two units
 * cannot both hash the same last line. Closing the descriptor also drops it. */
#if defined(_WIN32)
static int ledger_lock(int fd, bool exclusive)
{
    intptr_t raw = _get_osfhandle(fd);
    if (raw == -1) {
        errno = EBADF;
        return -1;
    }
    OVERLAPPED overlap;
    memset(&overlap, 0, sizeof(overlap));
    DWORD flags = LOCKFILE_FAIL_IMMEDIATELY |
                  (exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0);
    for (;;) {
        if (LockFileEx((HANDLE)raw, flags, 0, MAXDWORD, MAXDWORD, &overlap))
            return 0;
        DWORD error = GetLastError();
        if (error == ERROR_LOCK_VIOLATION) {
            Sleep(10);
            continue;
        }
        errno = error == ERROR_INVALID_HANDLE ? EBADF
              : error == ERROR_ACCESS_DENIED ? EACCES : EIO;
        return -1;
    }
}

static int ledger_unlock(int fd)
{
    intptr_t raw = _get_osfhandle(fd);
    if (raw == -1) {
        errno = EBADF;
        return -1;
    }
    OVERLAPPED overlap;
    memset(&overlap, 0, sizeof(overlap));
    if (!UnlockFileEx((HANDLE)raw, 0, MAXDWORD, MAXDWORD, &overlap)) {
        DWORD error = GetLastError();
        errno = error == ERROR_INVALID_HANDLE ? EBADF
              : error == ERROR_ACCESS_DENIED ? EACCES : EIO;
        return -1;
    }
    return 0;
}
#else
static int ledger_lock(int fd, bool exclusive)
{
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = exclusive ? F_WRLCK : F_RDLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    int rc;
    do {
        rc = fcntl(fd, F_SETLKW, &fl);
    } while (rc != 0 && errno == EINTR);
    return rc;
}

static int ledger_unlock(int fd)
{
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    return fcntl(fd, F_SETLK, &fl);
}
#endif

static bool head_path_of(const char *path, char *out, size_t cap)
{
    const size_t n = strlen(path);
    const size_t suffix = sizeof(ENGINE_RECEIPT_HEAD_SUFFIX) - 1u;
    if (n + suffix + 1u > cap)
        return false;
    memcpy(out, path, n);
    memcpy(out + n, ENGINE_RECEIPT_HEAD_SUFFIX, suffix + 1u);
    return true;
}

/* Write `path`.head as one 64-hex line. Called while the ledger fd is held
 * exclusive, so a concurrent append cannot publish a different pin first. */
static bool write_head_pin(const char *path, const char *sha3_hex)
{
    char hpath[4096];
    if (!head_path_of(path, hpath, sizeof(hpath)))
        LOG_FAIL("engine_receipt", "head path for %s is too long", path);
    const int fd = receipt_open(hpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        LOG_FAIL("engine_receipt", "cannot write the head pin for %s", path);
    char buf[65];
    memcpy(buf, sha3_hex, 64);
    buf[64] = '\n';
    const ssize_t wrote = write(fd, buf, 65);
    const int closed = close(fd);
    if (wrote != 65 || closed != 0)
        LOG_FAIL("engine_receipt", "short write of the head pin for %s", path);
    return true;
}

/* 1 = pin read, 0 = no such file, -1 = unreadable or malformed. */
static int read_head_pin(const char *path, char out[65])
{
    out[0] = '\0';
    char hpath[4096];
    if (!head_path_of(path, hpath, sizeof(hpath)))
        LOG_ERR("engine_receipt", "head path for %s is too long", path);
    const int fd = receipt_open(hpath, O_RDONLY, 0);
    if (fd < 0) {
        if (errno == ENOENT)
            return 0;
        LOG_ERR("engine_receipt", "cannot read the head pin for %s", path);
    }
    char buf[66];
    const ssize_t n = read(fd, buf, sizeof(buf));
    (void)close(fd);
    if (n != 65 || buf[64] != '\n')
        LOG_ERR("engine_receipt",
                "the head pin for %s is not a 64-hex line", path);
    for (int i = 0; i < 64; i++) {
        const char c = buf[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            LOG_ERR("engine_receipt",
                    "the head pin for %s is not lowercase hex", path);
    }
    memcpy(out, buf, 64);
    out[64] = '\0';
    return 1;
}

static void close_locked(int fd, const char *path)
{
    if (ledger_unlock(fd) != 0)
        LOG_WARN("engine_receipt", "cannot unlock %s: %s", path,
                 strerror(errno));
    if (close(fd) != 0)
        LOG_WARN("engine_receipt", "cannot close %s: %s", path,
                 strerror(errno));
}

/* Read the last complete line of the already-open, already-locked ledger
 * into `line`, without its newline.
 *
 * A file whose final byte is not a newline has a torn tail: some earlier
 * append did not finish. That is refused rather than repaired, because the
 * two available repairs — hashing the partial line, or dropping it — both
 * produce a chain that verifies over a history that is not what happened.
 *
 * Returns 1 with `line` filled, 0 when the file is empty (a genesis append),
 * and -1 on a refusal. */
static int read_last_line_fd(int fd, const char *path, char *line, size_t cap)
{
    line[0] = '\0';
    struct stat st;
    if (fstat(fd, &st) != 0)
        LOG_ERR("engine_receipt", "cannot size %s", path);
    if (st.st_size < 0)
        LOG_ERR("engine_receipt", "cannot size %s", path);
    if (st.st_size == 0)
        return 0;
    /* One line is bounded, so the tail we must look at is bounded too. */
    const size_t window = (size_t)st.st_size < cap ? (size_t)st.st_size : cap;
    if (lseek(fd, st.st_size - (off_t)window, SEEK_SET) == (off_t)-1)
        LOG_ERR("engine_receipt", "cannot seek the tail of %s", path);
    char *buf = line;
    const ssize_t got = read(fd, buf, window);
    if (got < 0 || (size_t)got != window)
        LOG_ERR("engine_receipt", "short read of the tail of %s", path);
    if (buf[got - 1] != '\n')
        LOG_ERR("engine_receipt",
                "refusing to append to %s: its last line has no newline, so a "
                "previous append did not finish and the chain cannot be "
                "continued honestly", path);
    /* Drop the trailing newline, then find the start of that final line. */
    size_t end = (size_t)got - 1;
    size_t start = 0;
    for (size_t i = end; i > 0; i--) {
        if (buf[i - 1] == '\n') {
            start = i;
            break;
        }
    }
    if (start == 0 && (size_t)st.st_size > window)
        LOG_ERR("engine_receipt",
                "refusing %s: its last line is longer than the %zu-byte cap",
                path, cap);
    const size_t n = end - start;
    memmove(line, buf + start, n);
    line[n] = '\0';
    return 1;
}

/* SHA3-256("zcl.engine_unit.id.v1\0" || task || "\0" || engine || "\0" || ts)
 * — see the header for why a same-second repeat is deliberately the same id. */
static void unit_id_of(const char *task_sha3, const char *engine, int64_t ts,
                       char out[65])
{
    char ts_dec[32];
    (void)snprintf(ts_dec, sizeof(ts_dec), "%lld", (long long)ts);
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    static const char k_domain[] = "zcl.engine_unit.id.v1";
    sha3_256_write(&ctx, (const unsigned char *)k_domain, sizeof(k_domain));
    sha3_256_write(&ctx, (const unsigned char *)or_empty(task_sha3),
                   strlen(or_empty(task_sha3)) + 1u);
    sha3_256_write(&ctx, (const unsigned char *)or_empty(engine),
                   strlen(or_empty(engine)) + 1u);
    sha3_256_write(&ctx, (const unsigned char *)ts_dec, strlen(ts_dec));
    uint8_t digest[32];
    sha3_256_finalize(&ctx, digest);
    zcl_hex_encode(digest, 32, out);
    out[64] = '\0';
}

static bool build_line(const struct engine_receipt *r, const char *prev_sha3,
                       char *out, size_t cap, size_t *out_len)
{
    char unit_id[65];
    unit_id_of(r->task_sha3, r->engine, r->ts, unit_id);

    struct json_value rules;
    json_init(&rules);
    json_set_array(&rules);
    bool ok = true;
    for (size_t i = 0; ok && i < r->rules_count; i++) {
        struct json_value s;
        json_init(&s);
        json_set_str(&s, or_empty(r->rules_shown ? r->rules_shown[i] : NULL));
        ok = json_push_back(&rules, &s);
        json_free(&s);
    }

    struct json_value outcome;
    json_init(&outcome);
    json_set_object(&outcome);
    ok = ok
        && json_push_kv_bool(&outcome, "applied", r->outcome.applied)
        && json_push_kv_int(&outcome, "groups_ran", r->outcome.groups_ran)
        && json_push_kv_int(&outcome, "groups_failed", r->outcome.groups_failed)
        && json_push_kv_bool(&outcome, "gate_pass", r->outcome.gate_pass)
        && json_push_kv_int(&outcome, "retries", r->outcome.retries)
        && json_push_kv_int(&outcome, "lines_changed", r->outcome.lines_changed)
        && json_push_kv_int(&outcome, "lint_rc", r->outcome.lint_rc);

    struct json_value invocations;
    json_init(&invocations);
    json_set_array(&invocations);
    int64_t total_prompt = 0;
    int64_t total_completion = 0;
    int64_t total_cache_read = 0;
    int64_t total_cache_creation = 0;
    int64_t total_reasoning = 0;
    int64_t total_reported = 0;
    int64_t total_invocation_elapsed = 0;
    bool invocation_elapsed_known = true;
    bool totals_known[6] = { true, true, true, true, true, true };
    for (size_t i = 0; ok && i < r->invocations_count; i++) {
        const struct engine_receipt_invocation *in = &r->invocations[i];
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        ok = json_push_kv_int(&item, "ordinal", in->ordinal)
            && json_push_kv_str(&item, "phase", or_empty(in->phase))
            && json_push_kv_str(&item, "result", or_empty(in->result))
            && json_push_kv_int(&item, "elapsed_ms", in->elapsed_ms)
            && json_push_kv_int(&item, "http_status", in->http_status)
            && push_nullable_string(&item, "resolved_model",
                                    in->resolved_model)
            && json_push_kv_int(&item, "prompt_tokens", in->prompt_tokens)
            && json_push_kv_int(&item, "completion_tokens",
                                in->completion_tokens)
            && json_push_kv_int(&item, "cache_read_input_tokens",
                                in->cache_read_input_tokens)
            && json_push_kv_int(&item, "cache_creation_input_tokens",
                                in->cache_creation_input_tokens)
            && json_push_kv_int(&item, "reasoning_tokens",
                                in->reasoning_tokens)
            && json_push_kv_int(&item, "total_tokens", in->total_tokens)
            && json_push_back(&invocations, &item);
        json_free(&item);

#define ADD_TOTAL(index, field, total) do {                                \
    const int64_t value = in->field;                                       \
    if (value < 0 || total > INT64_MAX - value)                            \
        totals_known[index] = false;                                       \
    else if (totals_known[index])                                          \
        total += value;                                                     \
} while (0)
        ADD_TOTAL(0, prompt_tokens, total_prompt);
        ADD_TOTAL(1, completion_tokens, total_completion);
        ADD_TOTAL(2, cache_read_input_tokens, total_cache_read);
        ADD_TOTAL(3, cache_creation_input_tokens, total_cache_creation);
        ADD_TOTAL(4, reasoning_tokens, total_reasoning);
        ADD_TOTAL(5, total_tokens, total_reported);
#undef ADD_TOTAL
        if (in->elapsed_ms < 0 ||
            total_invocation_elapsed > INT64_MAX - in->elapsed_ms)
            invocation_elapsed_known = false;
        else if (invocation_elapsed_known)
            total_invocation_elapsed += in->elapsed_ms;
    }
    if (r->invocations_count == 0 || r->invocation_totals_ambiguous) {
        for (size_t i = 0; i < 6; i++)
            totals_known[i] = false;
    }
    if (r->invocations_count == 0)
        invocation_elapsed_known = false;

    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    ok = ok
        && json_push_kv_str(&doc, "schema", ENGINE_RECEIPT_SCHEMA)
        && json_push_kv_str(&doc, "prev_sha3", prev_sha3)
        && json_push_kv_str(&doc, "unit_id", unit_id)
        && json_push_kv_int(&doc, "ts", r->ts)
        && json_push_kv_str(&doc, "engine", or_empty(r->engine))
        /* Retain the v1 reader's grouping key while making requested and
         * provider-reported identities independently observable. */
        && json_push_kv_str(&doc, "model", or_empty(r->requested_model))
        && json_push_kv_str(&doc, "requested_model",
                            or_empty(r->requested_model))
        && push_nullable_string(&doc, "resolved_model", r->resolved_model)
        && json_push_kv_str(&doc, "reasoning_effort",
                            or_empty(r->reasoning_effort))
        && json_push_kv_str(&doc, "kind", or_empty(r->kind))
        && json_push_kv_str(&doc, "template_sha3", or_empty(r->template_sha3))
        && json_push_kv(&doc, "rules_shown", &rules)
        && json_push_kv_str(&doc, "task_sha3", or_empty(r->task_sha3))
        && json_push_kv_str(&doc, "group", or_empty(r->group))
        && json_push_kv_str(&doc, "accounting_scope", "terminal_dispatch")
        && json_push_kv_int(&doc, "prompt_tokens", r->prompt_tokens)
        && json_push_kv_int(&doc, "completion_tokens", r->completion_tokens)
        && json_push_kv_int(&doc, "cache_read_input_tokens",
                            r->cache_read_input_tokens)
        && json_push_kv_int(&doc, "cache_creation_input_tokens",
                            r->cache_creation_input_tokens)
        && json_push_kv_int(&doc, "reasoning_tokens", r->reasoning_tokens)
        && json_push_kv_int(&doc, "total_tokens", r->total_tokens)
        && json_push_kv_int(&doc, "turns", r->turns)
        && json_push_kv(&doc, "invocations", &invocations)
        && json_push_kv_int(&doc, "total_prompt_tokens",
                            totals_known[0] ? total_prompt
                                            : ENGINE_RECEIPT_UNREPORTED)
        && json_push_kv_int(&doc, "total_completion_tokens",
                            totals_known[1] ? total_completion
                                            : ENGINE_RECEIPT_UNREPORTED)
        && json_push_kv_int(&doc, "total_cache_read_input_tokens",
                            totals_known[2] ? total_cache_read
                                            : ENGINE_RECEIPT_UNREPORTED)
        && json_push_kv_int(&doc, "total_cache_creation_input_tokens",
                            totals_known[3] ? total_cache_creation
                                            : ENGINE_RECEIPT_UNREPORTED)
        && json_push_kv_int(&doc, "total_reasoning_tokens",
                            totals_known[4] ? total_reasoning
                                            : ENGINE_RECEIPT_UNREPORTED)
        && json_push_kv_int(&doc, "total_reported_tokens",
                            totals_known[5] ? total_reported
                                            : ENGINE_RECEIPT_UNREPORTED)
        && json_push_kv_int(&doc, "total_invocation_elapsed_ms",
                            invocation_elapsed_known
                                ? total_invocation_elapsed
                                : ENGINE_RECEIPT_UNREPORTED)
        && json_push_kv_int(&doc, "cumulative_proof_ms",
                            r->cumulative_proof_ms)
        && json_push_kv_int(&doc, "unit_elapsed_ms", r->unit_elapsed_ms)
        && json_push_kv_int(&doc, "dispatch_ms", r->dispatch_ms)
        && json_push_kv_int(&doc, "proof_ms", r->proof_ms)
        && json_push_kv_int(&doc, "wall_ms", r->wall_ms)
        && json_push_kv_int(&doc, "http_status", r->http_status)
        && json_push_kv(&doc, "outcome", &outcome)
        && json_push_kv_str(&doc, "worktree_head", or_empty(r->worktree_head));
    json_free(&rules);
    json_free(&outcome);
    json_free(&invocations);
    if (!ok) {
        json_free(&doc);
        LOG_FAIL("engine_receipt", "cannot assemble the receipt document");
    }
    const size_t n = json_write(&doc, out, cap);
    json_free(&doc);
    if (n >= cap)
        LOG_FAIL("engine_receipt",
                 "refusing a %zu-byte receipt line: over the %u-byte cap. A "
                 "truncated line would break every link after it and read as "
                 "tampering", n, (unsigned)ENGINE_RECEIPT_LINE_MAX);
    *out_len = n;
    return true;
}

bool engine_receipt_fits(const struct engine_receipt *r)
{
    if (!r || !r->engine || !r->engine[0] || !r->requested_model ||
        !r->requested_model[0] || r->rules_count > ENGINE_RECEIPT_RULES_MAX ||
        r->invocations_count > ENGINE_RECEIPT_INVOCATIONS_MAX ||
        (r->invocations_count > 0 && !r->invocations) ||
        !r->reasoning_effort || !r->reasoning_effort[0] ||
        !engine_reasoning_effort_valid(r->reasoning_effort))
        return false;
    static const char zero[65] =
        "0000000000000000000000000000000000000000000000000000000000000000";
    char line[ENGINE_RECEIPT_LINE_MAX + 1u];
    size_t len = 0;
    return build_line(r, zero, line, ENGINE_RECEIPT_LINE_MAX, &len);
}

bool engine_receipt_append(const char *path, const struct engine_receipt *r,
                           char *out_line_sha3)
{
    if (out_line_sha3)
        out_line_sha3[0] = '\0';
    if (!path || !path[0] || !r)
        LOG_FAIL("engine_receipt", "refusing an append with no path or record");
    if (!r->engine || !r->engine[0])
        LOG_FAIL("engine_receipt",
                 "refusing a receipt with no engine id: a cost nobody can "
                 "attribute is not a measurement");
    if (!r->requested_model || !r->requested_model[0])
        LOG_FAIL("engine_receipt", "refusing a receipt with no requested model");
    if (r->rules_count > ENGINE_RECEIPT_RULES_MAX)
        LOG_FAIL("engine_receipt",
                 "refusing %zu rule ids: over the cap of %u", r->rules_count,
                 (unsigned)ENGINE_RECEIPT_RULES_MAX);
    if (r->invocations_count > ENGINE_RECEIPT_INVOCATIONS_MAX)
        LOG_FAIL("engine_receipt",
                 "refusing %zu invocations: over the complete-record cap of %u",
                 r->invocations_count,
                 (unsigned)ENGINE_RECEIPT_INVOCATIONS_MAX);
    if (r->invocations_count > 0 && !r->invocations)
        LOG_FAIL("engine_receipt", "refusing a non-empty NULL invocation list");
    if (!r->reasoning_effort || !r->reasoning_effort[0] ||
        !engine_reasoning_effort_valid(r->reasoning_effort))
        LOG_FAIL("engine_receipt", "refusing an invalid reasoning effort");

    /* O_RDWR because this same fd must read the tail; O_APPEND so the one
     * write(2) cannot overwrite earlier records even if the lock is lost.
     * The lock then makes the tail-read and that write one critical section. */
    const int fd = receipt_open(path, O_RDWR | O_CREAT | O_APPEND, 0644);
    if (fd < 0)
        LOG_FAIL("engine_receipt", "cannot open %s for append", path);
    if (ledger_lock(fd, true) != 0) {
        (void)close(fd);
        LOG_FAIL("engine_receipt", "cannot lock %s for append", path);
    }

    char last[ENGINE_RECEIPT_LINE_MAX + 2u];
    const int have = read_last_line_fd(fd, path, last,
                                       ENGINE_RECEIPT_LINE_MAX + 1u);
    if (have < 0) {
        close_locked(fd, path);
        return false;
    }

    char prev[65];
    if (have == 1) {
        sha3_hex(last, strlen(last), prev);
    } else {
        /* Genesis. 64 zeros, never an empty string: a reader that cannot
         * tell "first record" from "field missing" cannot tell a new file
         * from a spliced one. */
        memset(prev, '0', 64);
        prev[64] = '\0';
    }

    char line[ENGINE_RECEIPT_LINE_MAX + 2u];
    size_t len = 0;
    if (!build_line(r, prev, line, ENGINE_RECEIPT_LINE_MAX, &len)) {
        close_locked(fd, path);
        return false;
    }

    line[len] = '\n';
    const ssize_t wrote = write(fd, line, len + 1u);
    if (wrote != (ssize_t)(len + 1u)) {
        close_locked(fd, path);
        LOG_FAIL("engine_receipt", "short write appending to %s", path);
    }

    char hex[65];
    sha3_hex(line, len, hex);
    if (!write_head_pin(path, hex)) {
        close_locked(fd, path);
        return false;
    }
    close_locked(fd, path);
    if (out_line_sha3)
        memcpy(out_line_sha3, hex, 65);
    return true;
}

bool engine_receipt_verify_chain(const char *path,
                                 struct engine_receipt_chain_report *report)
{
    if (!report)
        LOG_FAIL("engine_receipt", "verify needs a report to fill");
    memset(report, 0, sizeof(*report));
    memset(report->head_sha3, '0', 64);
    report->head_sha3[64] = '\0';
    if (!path || !path[0])
        LOG_FAIL("engine_receipt", "verify needs a path");

    const int fd = receipt_open(path, O_RDONLY, 0);
    if (fd < 0) {
        if (errno != ENOENT)
            LOG_FAIL("engine_receipt", "cannot open %s to verify", path);
        /* No chainlog. A leftover head pin means the records were deleted. */
        char pinned[65];
        const int have_pin = read_head_pin(path, pinned);
        if (have_pin != 0) {
            report->first_bad_line = 1;
            (void)snprintf(report->why, sizeof(report->why),
                           have_pin < 0
                               ? "the head pin for a missing chainlog is unreadable"
                               : "the chainlog is gone but its head pin remains");
            return false;
        }
        return true;          /* no file is an empty chain, not a broken one */
    }
    if (ledger_lock(fd, false) != 0) {
        (void)close(fd);
        LOG_FAIL("engine_receipt", "cannot lock %s to verify", path);
    }
    FILE *f = fdopen(fd, "rb");
    if (!f) {
        close_locked(fd, path);
        LOG_FAIL("engine_receipt", "cannot read %s to verify", path);
    }

    char expect[65];
    memset(expect, '0', 64);
    expect[64] = '\0';

    char line[ENGINE_RECEIPT_LINE_MAX + 2u];
    uint64_t lineno = 0;
    bool ok = true;
    while (ok && fgets(line, (int)sizeof(line), f)) {
        lineno++;
        size_t n = strlen(line);
        if (n == 0 || line[n - 1] != '\n') {
            report->first_bad_line = lineno;
            (void)snprintf(report->why, sizeof(report->why),
                           "line %llu has no newline: an append did not finish",
                           (unsigned long long)lineno);
            ok = false;
            break;
        }
        line[--n] = '\0';

        struct json_value doc;
        json_init(&doc);
        if (!json_read(&doc, line, n) || doc.type != JSON_OBJ) {
            json_free(&doc);
            report->first_bad_line = lineno;
            (void)snprintf(report->why, sizeof(report->why),
                           "line %llu is not a JSON object",
                           (unsigned long long)lineno);
            ok = false;
            break;
        }
        const struct json_value *pv = json_get(&doc, "prev_sha3");
        const char *ps = (pv && pv->type == JSON_STR) ? json_get_str(pv) : NULL;
        const bool linked = ps && strcmp(ps, expect) == 0;
        json_free(&doc);
        if (!linked) {
            report->first_bad_line = lineno;
            (void)snprintf(report->why, sizeof(report->why),
                           "line %llu carries the wrong prev_sha3: an earlier "
                           "line was edited, removed, or reordered",
                           (unsigned long long)lineno);
            ok = false;
            break;
        }
        sha3_hex(line, n, expect);
        (void)snprintf(report->head_sha3, sizeof(report->head_sha3), "%s",
                       expect);
        report->records++;
    }
    if (ok && ferror(f)) {
        report->first_bad_line = lineno + 1u;
        (void)snprintf(report->why, sizeof(report->why),
                       "a read of %s failed after line %llu", path,
                       (unsigned long long)lineno);
        ok = false;
    }

    if (ok) {
        char pinned[65];
        const int have_pin = read_head_pin(path, pinned);
        if (have_pin < 0) {
            report->first_bad_line = report->records ? report->records : 1;
            (void)snprintf(report->why, sizeof(report->why),
                           "the head pin for %s is unreadable", path);
            ok = false;
        } else if (report->records == 0) {
            if (have_pin == 1) {
                report->first_bad_line = 1;
                (void)snprintf(report->why, sizeof(report->why),
                               "an empty chain still has a head pin: the "
                               "records were removed");
                ok = false;
            }
        } else if (have_pin == 0) {
            report->first_bad_line = report->records;
            (void)snprintf(report->why, sizeof(report->why),
                           "the chain has no pinned head, so a rewritten last "
                           "line would not be visible");
            ok = false;
        } else if (strcmp(pinned, report->head_sha3) != 0) {
            report->first_bad_line = report->records;
            (void)snprintf(report->why, sizeof(report->why),
                           "the last line does not match the pinned head: "
                           "the tail was rewritten");
            ok = false;
        }
    }

    if (ledger_unlock(fd) != 0)
        LOG_WARN("engine_receipt", "cannot unlock %s after verify: %s", path,
                 strerror(errno));
    if (fclose(f) != 0)
        LOG_WARN("engine_receipt", "cannot close %s after verify: %s", path,
                 strerror(errno));
    return ok;
}
