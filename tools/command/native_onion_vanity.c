/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * core.network.onion.vanity: search for an ed25519 seed whose v3 onion
 * address begins with a chosen prefix and write the seed, mode 0600, to a
 * caller-named file. The command never touches a node data directory, never
 * starts Tor, and never prints the seed. The seed file is the 32 raw bytes
 * onion_identity_ensure() reads as <datadir>/tor_data/onion_service/
 * identity_seed.
 *
 * Dispatch: the only production caller of the command registry is the argv
 * path in native_command.c, which runs in the short-lived CLI process; the
 * leaf has no RPC or REST transport and its remote class is NEVER. While a
 * search runs, this handler holds SIGINT and SIGTERM (both stop the search)
 * and restores the previous dispositions before returning. */

#include "command/native_command.h"
#include "command/onion_vanity.h"

#include "controllers/native_handler_body.h"
#include "crypto/random_secret.h"
#include "json/json.h"
#include "net/tor_integration.h"
#include "platform/logical_cpu.h"
#include "platform/private_file.h"
#include "support/cleanse.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

#define OV_PATH_MAX 1024
#define OV_CALIBRATION_NS INT64_C(200000000)
#define OV_LONG_SEARCH_SECONDS 3600.0
#define OV_TIMEOUT_MAX_S INT64_C(31536000)

static volatile sig_atomic_t g_ov_interrupt;

static void ov_on_signal(int signo)
{
    (void)signo;
    g_ov_interrupt = 1;
}

/* Installs ov_on_signal for `signo` and saves what was in force. sigaction,
 * not signal(): this tree builds with -D_POSIX_C_SOURCE and -std=c23, where
 * glibc maps signal() to the System V one-shot form (SA_RESETHAND), so the
 * first signal would reset the disposition to SIG_DFL and a second SIGINT
 * before the restore would kill the process. Windows has no sigaction; its
 * CRT signal() is the only install there. */
#if !defined(_WIN32)
typedef struct sigaction ov_sig_saved;

static bool ov_signal_hold(int signo, ov_sig_saved *prev)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = ov_on_signal;
    sigemptyset(&sa.sa_mask);
    return sigaction(signo, &sa, prev) == 0;
}

static void ov_signal_restore(int signo, const ov_sig_saved *prev)
{
    (void)sigaction(signo, prev, NULL);
}
#else
typedef void (*ov_sig_saved)(int);

static bool ov_signal_hold(int signo, ov_sig_saved *prev)
{
    *prev = signal(signo, ov_on_signal); // signal-oneshot-ok: no sigaction on Windows
    return *prev != SIG_ERR;
}

static void ov_signal_restore(int signo, const ov_sig_saved *prev)
{
    (void)signal(signo, *prev); // signal-oneshot-ok: no sigaction on Windows
}
#endif

struct ov_request {
    struct onion_vanity_target target;
    char out[OV_PATH_MAX];
    unsigned threads;
    uint64_t max_tries;
    int64_t timeout_s;
    bool estimate_only;
    bool accept_long;
};

static void ov_fail(struct zcl_command_reply *reply, enum zcl_command_exit exit_code,
                    const char *code, const char *message, const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code,
                           "normalize", false, false, message, evidence);
}

static bool ov_parse_prefix(const struct json_value *in, struct ov_request *req,
                            struct zcl_command_reply *reply)
{
    const char *prefix = json_get_str_or(in, "prefix", "");
    char bad = 0;
    char message[160];
    switch (onion_vanity_target_parse(prefix, &req->target, &bad)) {
    case ONION_VANITY_PREFIX_OK:
        return true;
    case ONION_VANITY_PREFIX_EMPTY:
        ov_fail(reply, ZCL_COMMAND_EXIT_INVALID, "PREFIX_EMPTY",
                "prefix must have at least one character", "prefix");
        return false;
    case ONION_VANITY_PREFIX_TOO_LONG:
        snprintf(message, sizeof(message), "prefix is longer than %d characters",
                 ONION_VANITY_PREFIX_MAX);
        ov_fail(reply, ZCL_COMMAND_EXIT_INVALID, "PREFIX_TOO_LONG", message,
                "prefix");
        return false;
    default:
        snprintf(message, sizeof(message),
                 "character 0x%02x is not in the v3 onion alphabet a-z 2-7",
                 (unsigned)(unsigned char)bad);
        ov_fail(reply, ZCL_COMMAND_EXIT_INVALID, "PREFIX_BAD_CHAR", message,
                "prefix");
        return false;
    }
}

/* Reads an optional integer key bounded to [lo, hi]. */
static bool ov_bounded(const struct json_value *in, const char *key, int64_t lo,
                       int64_t hi, int64_t *value,
                       struct zcl_command_reply *reply, const char *code)
{
    const struct json_value *v = json_get(in, key);
    if (!v)
        return true;
    int64_t n = json_get_int(v);
    if (n >= lo && n <= hi) {
        *value = n;
        return true;
    }
    ov_fail(reply, ZCL_COMMAND_EXIT_INVALID, code,
            "value is outside the accepted range", key);
    return false;
}

static unsigned ov_default_threads(void)
{
    uint32_t cpus = platform_available_cpu_count();
    uint32_t n = cpus > 1 ? cpus - 1 : 1;
    return n > ONION_VANITY_THREADS_MAX ? ONION_VANITY_THREADS_MAX : n;
}

static bool ov_parse_request(const struct json_value *in, struct ov_request *req,
                             struct zcl_command_reply *reply)
{
    int64_t threads = ov_default_threads(), max_tries = 0, timeout_s = 0;
    req->estimate_only = json_get_bool_or(in, "estimate_only", false);
    req->accept_long = json_get_bool_or(in, "accept_long_search", false);
    const char *out = json_get_str_or(in, "output_path", "");
    if (!ov_parse_prefix(in, req, reply) ||
        !ov_bounded(in, "threads", 1, ONION_VANITY_THREADS_MAX, &threads, reply,
                    "THREADS_OUT_OF_RANGE") ||
        !ov_bounded(in, "max_tries", 1, INT64_MAX, &max_tries, reply,
                    "MAX_TRIES_OUT_OF_RANGE") ||
        !ov_bounded(in, "timeout_s", 1, OV_TIMEOUT_MAX_S, &timeout_s, reply,
                    "TIMEOUT_OUT_OF_RANGE"))
        return false;
    if (!req->estimate_only && (!out[0] || strlen(out) >= sizeof(req->out))) {
        ov_fail(reply, ZCL_COMMAND_EXIT_INVALID, "OUT_PATH_INVALID",
                "output_path must name a file path of 1 to 1023 bytes", "output_path");
        return false;
    }
    snprintf(req->out, sizeof(req->out), "%s", out);
    req->threads = (unsigned)threads;
    req->max_tries = (uint64_t)max_tries;
    req->timeout_s = timeout_s;
    return true;
}

struct ov_estimate {
    double expected_tries;
    double rate;
    double expected_seconds; /* time to a mean match */
    double bound_seconds;    /* the least of mean time and the caller's bounds */
};

static void ov_estimate_fill(const struct ov_request *req, double rate,
                             struct ov_estimate *est)
{
    est->expected_tries = onion_vanity_expected_tries(&req->target);
    est->rate = rate;
    est->expected_seconds = est->expected_tries / rate;
    est->bound_seconds = est->expected_seconds;
    if (req->max_tries && (double)req->max_tries / rate < est->bound_seconds)
        est->bound_seconds = (double)req->max_tries / rate;
    if (req->timeout_s && (double)req->timeout_s < est->bound_seconds)
        est->bound_seconds = (double)req->timeout_s;
}

static void ov_estimate_json(struct json_value *data, const struct ov_request *req,
                             const struct ov_estimate *est)
{
    struct json_value e;
    json_init(&e);
    json_set_object(&e);
    (void)json_push_kv_str(&e, "prefix", req->target.text);
    (void)json_push_kv_int(&e, "prefix_length", (int64_t)req->target.length);
    (void)json_push_kv_real(&e, "expected_tries", est->expected_tries);
    (void)json_push_kv_real(&e, "tries_per_second", est->rate);
    (void)json_push_kv_real(&e, "expected_seconds", est->expected_seconds);
    (void)json_push_kv_int(&e, "threads", req->threads);
    (void)json_push_kv_int(&e, "calibration_ms", OV_CALIBRATION_NS / 1000000);
    (void)json_push_kv_bool(&e, "exceeds_one_hour",
                            est->expected_seconds > OV_LONG_SEARCH_SECONDS);
    (void)json_push_kv_bool(&e, "requires_accept_long_search",
                            est->bound_seconds > OV_LONG_SEARCH_SECONDS);
    (void)json_push_kv(data, "estimate", &e);
    json_free(&e);
}

enum ov_write_status {
    OV_WRITE_OK,
    OV_WRITE_EXISTS,
    OV_WRITE_FAILED,
    OV_WRITE_NO_RANDOM,
    OV_WRITE_UNCONFIRMED, /* renamed into place; directory flush unconfirmed */
};

static bool ov_stage_name(const char *out, char *stage, size_t size)
{
    uint8_t tag[4];
    if (!zcl_random_secret_bytes(tag, sizeof(tag), "onion_vanity_stage"))
        return false;
    snprintf(stage, size, "%s.tmp-%02x%02x%02x%02x", out, tag[0], tag[1],
             tag[2], tag[3]);
    return true;
}

/* Writes the 32 seed bytes to a private staging file, flushes them to stable
 * storage, and renames it onto `out` without replacing an existing file. */
static enum ov_write_status ov_write_seed(const char *out, const uint8_t seed[32])
{
    char resolved[OV_PATH_MAX], parent[OV_PATH_MAX], stage[OV_PATH_MAX + 16];
    if (!platform_private_destination_resolve(out, resolved, sizeof(resolved),
                                              parent, sizeof(parent)))
        return OV_WRITE_FAILED;
    if (!platform_private_path_absent(resolved))
        return OV_WRITE_EXISTS;
    if (!ov_stage_name(resolved, stage, sizeof(stage)))
        return OV_WRITE_NO_RANDOM;

    struct platform_private_file file;
    struct platform_private_file_identity id;
    platform_private_file_init(&file);
    if (!platform_private_file_create(stage, &file))
        return OV_WRITE_FAILED;
    bool exists = false;
    bool have_id = platform_private_file_identity(&file, &id);
    bool ok = have_id && platform_private_file_write_at(&file, seed, 32, 0) &&
              platform_private_file_truncate(&file, 32) &&
              platform_private_file_authority_flush(&file) &&
              platform_private_file_publish_no_clobber(&file, stage, resolved,
                                                       &exists);
    if (!ok || exists) {
        if (have_id)
            (void)platform_private_file_retire_if_identity(&file, stage, &id);
        platform_private_file_close(&file);
        return exists ? OV_WRITE_EXISTS : OV_WRITE_FAILED;
    }
    return platform_private_parent_flush(parent) ? OV_WRITE_OK
                                                 : OV_WRITE_UNCONFIRMED;
}

static void ov_search_failed(struct zcl_command_reply *reply,
                             const struct onion_vanity_result *res)
{
    char message[96];
    const char *code = "SEARCH_FAILED";
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    if (res->status == ONION_VANITY_EXHAUSTED) {
        code = "NOT_FOUND_MAX_TRIES";
        exit_code = ZCL_COMMAND_EXIT_FAILED;
    } else if (res->status == ONION_VANITY_TIMED_OUT) {
        code = "NOT_FOUND_TIMEOUT";
        exit_code = ZCL_COMMAND_EXIT_FAILED;
    } else if (res->status == ONION_VANITY_INTERRUPTED) {
        code = "INTERRUPTED";
        exit_code = ZCL_COMMAND_EXIT_TRANSIENT;
    }
    snprintf(message, sizeof(message), "no file written after %llu tries",
             (unsigned long long)res->tries);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code,
                           "search", false, false, message, "prefix");
}

static void ov_found_json(struct zcl_command_reply *reply,
                          const struct ov_request *req, const char *address,
                          const struct onion_vanity_result *res,
                          const char *warning)
{
    double seconds = (double)res->elapsed_ns / 1e9;
    char full[80];
    snprintf(full, sizeof(full), "%s.onion", address);
    struct json_value *d = &reply->data;
    json_set_object(d);
    (void)json_push_kv_str(d, "status", "found");
    (void)json_push_kv_str(d, "address", full);
    (void)json_push_kv_str(d, "prefix", req->target.text);
    (void)json_push_kv_int(d, "tries", (int64_t)res->tries);
    (void)json_push_kv_real(d, "seconds", seconds);
    (void)json_push_kv_real(d, "tries_per_second",
                            seconds > 0 ? (double)res->tries / seconds : 0.0);
    (void)json_push_kv_int(d, "threads", req->threads);
    (void)json_push_kv_real(d, "expected_tries",
                            onion_vanity_expected_tries(&req->target));
    (void)json_push_kv_str(d, "output_path", req->out);
    if (warning)
        (void)json_push_kv_str(d, "warning", warning);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* Verifies the winner through the production derivation, then writes it. */
static void ov_finish_found(struct zcl_command_reply *reply,
                            const struct ov_request *req,
                            const struct onion_vanity_result *res)
{
    char address[64];
    if (!onion_identity_address_from_seed(res->seed, address, sizeof(address)) ||
        strncmp(address, req->target.text, req->target.length) != 0) {
        ov_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "VERIFY_MISMATCH",
                "winning seed did not derive the requested prefix; no file "
                "written", "prefix");
        return;
    }
    enum ov_write_status w = ov_write_seed(req->out, res->seed);
    if (w == OV_WRITE_EXISTS)
        ov_fail(reply, ZCL_COMMAND_EXIT_BLOCKED, "OUT_EXISTS",
                "output_path already exists; nothing was overwritten", "output_path");
    else if (w == OV_WRITE_NO_RANDOM)
        ov_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "SEARCH_FAILED",
                "the random source failed; no file written", "output_path");
    else if (w == OV_WRITE_FAILED)
        ov_fail(reply, ZCL_COMMAND_EXIT_FAILED, "OUT_WRITE_FAILED",
                "the seed file could not be written", "output_path");
    else
        ov_found_json(reply, req, address, res,
                      w == OV_WRITE_UNCONFIRMED
                          ? "the seed file is in place but the directory "
                            "flush was not confirmed"
                          : NULL);
}

static bool ov_out_available(const struct ov_request *req,
                             struct zcl_command_reply *reply)
{
    char resolved[OV_PATH_MAX], parent[OV_PATH_MAX];
    if (!platform_private_destination_resolve(req->out, resolved,
                                              sizeof(resolved), parent,
                                              sizeof(parent))) {
        ov_fail(reply, ZCL_COMMAND_EXIT_INVALID, "OUT_PATH_INVALID",
                "the parent directory of output_path does not exist", "output_path");
        return false;
    }
    if (!platform_private_path_absent(resolved)) {
        ov_fail(reply, ZCL_COMMAND_EXIT_BLOCKED, "OUT_EXISTS",
                "output_path already exists; nothing was overwritten", "output_path");
        return false;
    }
    return true;
}

static void ov_run(const struct ov_request *req, struct zcl_command_reply *reply)
{
    double rate = onion_vanity_measure_rate(req->threads, OV_CALIBRATION_NS,
                                            &g_ov_interrupt);
    if (rate <= 0.0) {
        if (g_ov_interrupt)
            ov_fail(reply, ZCL_COMMAND_EXIT_TRANSIENT, "INTERRUPTED",
                    "interrupted; no file written", "prefix");
        else
            ov_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "CALIBRATION_FAILED",
                    "the key generation rate could not be measured",
                    "threads");
        return;
    }
    struct ov_estimate est;
    ov_estimate_fill(req, rate, &est);
    if (req->estimate_only) {
        json_set_object(&reply->data);
        ov_estimate_json(&reply->data, req, &est);
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = ZCL_COMMAND_EXIT_OK;
        return;
    }
    if (est.bound_seconds > OV_LONG_SEARCH_SECONDS && !req->accept_long) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "SEARCH_TOO_LONG",
                               "estimate", false, false,
                               "expected search time exceeds one hour; run "
                               "with estimate_only for the figures, or pass "
                               "accept_long_search", "accept_long_search");
        return;
    }
    if (!ov_out_available(req, reply))
        return;
    struct onion_vanity_params params = {
        .target = req->target, .threads = req->threads,
        .max_tries = req->max_tries,
        .timeout_ns = req->timeout_s * INT64_C(1000000000),
        .interrupt = &g_ov_interrupt,
    };
    struct onion_vanity_result res;
    onion_vanity_search(&params, &res);
    if (res.status == ONION_VANITY_FOUND)
        ov_finish_found(reply, req, &res);
    else
        ov_search_failed(reply, &res);
    memory_cleanse(res.seed, sizeof(res.seed));
}

void zcl_native_handle_core_network_onion_vanity(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    struct ov_request req;
    memset(&req, 0, sizeof(req));
    if (!ov_parse_request(request->input, &req, reply))
        return;
    g_ov_interrupt = 0;
    ov_sig_saved prev_int, prev_term;
    bool have_int = ov_signal_hold(SIGINT, &prev_int);
    bool have_term = ov_signal_hold(SIGTERM, &prev_term);
    ov_run(&req, reply);
    if (have_int)
        ov_signal_restore(SIGINT, &prev_int);
    if (have_term)
        ov_signal_restore(SIGTERM, &prev_term);
}
