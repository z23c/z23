/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#define _GNU_SOURCE
#include "devloop.h"
#include "dev_failure_store.h"

#include "base/hex.h"
#include "crypto/sha3.h"
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include "platform/time_compat.h"
#include "vcs/vcs_devloop.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char *bounded_find(const char *haystack, size_t haystack_len,
                                const char *needle, size_t needle_len)
{
    if (!haystack || !needle || needle_len == 0 ||
        needle_len > haystack_len)
        return NULL;
    size_t last = haystack_len - needle_len;
    for (size_t i = 0; i <= last; ++i)
        if (haystack[i] == needle[0] &&
            memcmp(haystack + i, needle, needle_len) == 0)
            return haystack + i;
    return NULL;
}

static bool appendf(char *out, size_t cap, size_t *pos,
                    const char *fmt, ...)
{
    if (!out || !pos || *pos >= cap)
        return false;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out + *pos, cap - *pos, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= cap - *pos)
        return false;
    *pos += (size_t)n;
    return true;
}

static bool append_string(char *out, size_t cap, size_t *pos,
                          const char *value)
{
    if (!appendf(out, cap, pos, "\""))
        return false;
    for (const unsigned char *p = (const unsigned char *)(value ? value : "");
         *p; p++) {
        if (*p == '"' || *p == '\\') {
            if (!appendf(out, cap, pos, "\\%c", *p))
                return false;
        } else if (*p == '\n') {
            if (!appendf(out, cap, pos, "\\n"))
                return false;
        } else if (*p == '\r') {
            if (!appendf(out, cap, pos, "\\r"))
                return false;
        } else if (*p < 0x20) {
            if (!appendf(out, cap, pos, "\\u%04x", *p))
                return false;
        } else if (!appendf(out, cap, pos, "%c", *p)) {
            return false;
        }
    }
    return appendf(out, cap, pos, "\"");
}

/* Scan [out, out+len) FORWARD line-by-line for the first ACTIONABLE line —
 * a compiler diagnostic (a line containing ": error:") or a test failure (a
 * line containing "FAIL", "Assertion", or "EXPECT") — and copy it (newline
 * stripped, bounded by dstcap) into dst. Returns true iff one was found; dst
 * is always NUL-terminated. Pure: no I/O, no allocation. Static so the real
 * capsule builder can call it directly; a thin non-static wrapper below lets
 * the ZCL_TESTING harness exercise this pure function without ZCL_DEV_BUILD.
 * Guarded ZCL_DEV_BUILD||ZCL_TESTING so the test binary (which defines only
 * ZCL_TESTING) compiles and reaches it. */
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
static bool distill_first_error(const char *out, size_t len,
                                char *dst, size_t dstcap)
{
    if (!out || !dst || dstcap == 0)
        return false;
    dst[0] = 0;
    size_t i = 0;
    while (i < len) {
        size_t start = i;
        while (i < len && out[i] != '\n' && out[i] != '\r')
            i++;
        size_t line_len = i - start;
        while (i < len && (out[i] == '\n' || out[i] == '\r'))
            i++;
        if (line_len == 0)
            continue;
        const char *line = out + start;
        bool hit = bounded_find(line, line_len, ": error:", 8) != NULL ||
                   bounded_find(line, line_len, "FAIL", 4) != NULL ||
                   bounded_find(line, line_len, "Assertion", 9) != NULL ||
                   bounded_find(line, line_len, "EXPECT", 6) != NULL;
        if (hit) {
            size_t copy = line_len < dstcap - 1 ? line_len : dstcap - 1;
            memcpy(dst, line, copy);
            dst[copy] = 0;
            return true;
        }
    }
    return false;
}

/* Thin testable wrapper — distill_first_error is static; the ZCL_TESTING
 * harness drives it through this. Also keeps the static function "used" in a
 * ZCL_TESTING-only build (where output_capsule below is compiled out). */
bool zcl_devloop_distill_first_error(const char *out, size_t len,
                                     char *dst, size_t dstcap)
{
    return distill_first_error(out, len, dst, dstcap);
}
#endif /* ZCL_DEV_BUILD || ZCL_TESTING */

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
static bool compiler_error_shape(const char *line, size_t len)
{
    static const char marker[] = ": error:";
    static const char *const transient[] = {
        "No space left", "Input/output error", "I/O error", "Killed",
        "out of memory", "Out of memory", "cannot allocate memory",
        "Cannot allocate memory", "internal compiler error",
        "Internal compiler error", "resource temporarily unavailable",
        "Resource temporarily unavailable", "Permission denied",
        "Operation not permitted", "Read-only file system", "ccache",
        "sccache"
    };
    for (size_t i = 0; i < sizeof(transient) / sizeof(transient[0]); i++)
        if (bounded_find(line, len, transient[i], strlen(transient[i])) != NULL)
            return false;
    const char *end = line + len;
    for (const char *p = line; p < end; p++) {
        if (*p != ':' || p + 1 >= end || !isdigit((unsigned char)p[1]))
            continue;
        const char *q = p + 1;
        while (q < end && isdigit((unsigned char)*q))
            q++;
        if (q >= end || *q != ':' || q + 1 >= end ||
            !isdigit((unsigned char)q[1]))
            continue;
        q++;
        while (q < end && isdigit((unsigned char)*q))
            q++;
        if ((size_t)(end - q) >= sizeof(marker) - 1 &&
            memcmp(q, marker, sizeof(marker) - 1) == 0)
            return true;
    }
    return false;
}

/* Initial negative-cache allowlist: deterministic compiler diagnostics only.
 * Tests, lint, timeouts, signals, infrastructure/lock failures, and malformed
 * output always execute again. The exact marker must be a line emitted by the
 * fail-fast driver and its body must retain a compiler path/line/column
 * diagnostic after explicit infrastructure exclusions. */
#ifndef ZCL_HOTFORK_DEVLOOP_CYCLE_CORE
bool zcl_devloop_deterministic_compile_failure(
    const struct zcl_devloop_process_result *result,
    char out[ZCL_DEVLOOP_FIRST_ERROR_MAX])
{
    _Static_assert(ZCL_DEVLOOP_FIRST_ERROR_MAX == ZCL_DEV_FAILURE_ERROR_MAX,
                   "failure classifier and store limits must agree");
    if (!result || result->timed_out || result->term_signal != 0 ||
        result->output_truncated || result->exit_code == 0)
        return false;
    static const char marker[] =
        "[agent-fast-ci] FIRST-ERROR[compile]: ";
    const char *p = result->output;
    const char *end_output = result->output + result->output_len;
    const char *match = NULL;
    while (p < end_output) {
        const char *found = bounded_find(
            p, (size_t)(end_output - p), marker, sizeof(marker) - 1);
        if (!found)
            break;
        if (found == result->output || found[-1] == '\n' || found[-1] == '\r')
            match = found;
        p = found + sizeof(marker) - 1;
    }
    if (!match)
        return false;
    p = match + sizeof(marker) - 1;
    const char *end = p;
    while (end < end_output && *end != '\r' && *end != '\n')
        end++;
    size_t len = (size_t)(end - p);
    if (len == 0 || len >= ZCL_DEV_FAILURE_ERROR_MAX ||
        !compiler_error_shape(p, len))
        return false;
    char raw[ZCL_DEV_FAILURE_ERROR_MAX];
    memcpy(raw, p, len);
    raw[len] = 0;
    return zcl_dev_failure_normalize_error(raw, out);
}
#endif
#endif

bool zcl_devloop_watch_lock_path(const char *repo_root,
                                 char *out, size_t out_sz)
{
    if (!repo_root || !repo_root[0] || !out || out_sz == 0)
        return false;
    int n = snprintf(out, out_sz, "%s/%s", repo_root,
                     ZCL_DEVLOOP_WATCH_LOCK_REL);
    return n > 0 && (size_t)n < out_sz;
}

#ifdef ZCL_DEV_BUILD
static void output_capsule(const struct zcl_devloop_process_result *result,
                           char out[1024])
{
    if (!result || result->output_len == 0) {
        out[0] = 0;
        return;
    }

    /* Dense capsule (A4): lead with the first actionable error line so the
     * agent sees the root cause without paging the tail. Fail-open — when no
     * pattern matches, the existing last-N-bytes tail is the whole body, so
     * nothing regresses. */
    size_t pos = 0;
    char first[512];
    if (distill_first_error(result->output, result->output_len,
                            first, sizeof(first))) {
        int n = snprintf(out, 1024, "first_error=%s\n", first);
        if (n > 0 && (size_t)n < 1024)
            pos = (size_t)n;
    }

    const char *start = result->output;
    size_t len = result->output_len;
    if (len > 900) {
        start += len - 900;
        len = 900;
    }
    while (len > 0 && (*start == '\n' || *start == '\r')) {
        start++;
        len--;
    }
    /* Bound the tail so first_error + tail never overflow out[1024]. */
    if (len > 1024 - 1 - pos)
        len = 1024 - 1 - pos;
    memcpy(out + pos, start, len);
    out[pos + len] = 0;
}

struct cycle_failure_context {
    struct dev_source_record source;
    char execution_id[65];
    char failure_id[65];
    char failure_phase[ZCL_DEV_FAILURE_PHASE_MAX];
    char first_error[ZCL_DEV_FAILURE_ERROR_MAX];
    char store_error[192];
    uint64_t repeat_count;
    bool source_ready;
    bool execution_ready;
    bool cacheable;
    bool coalesced;
};

/* A cycle is synchronous, but the native dispatcher can be called by more
 * than one dev process/thread.  Thread-local evidence avoids a process-global
 * latest-failure race while keeping the many finish_cycle() exits compact. */
static _Thread_local struct cycle_failure_context g_cycle_failure;

static void cycle_failure_reset(void)
{
    memset(&g_cycle_failure, 0, sizeof(g_cycle_failure));
}

static bool result_ok(const struct zcl_devloop_process_result *result)
{
    return result && !result->timed_out && result->term_signal == 0 &&
           result->exit_code == 0;
}

static bool repo_root_resolve(const char *requested, char out[PATH_MAX])
{
    const char *root = requested && requested[0] ? requested : ".";
    if (!platform_directory_canonical_real(root, out, PATH_MAX))
        return false;
    char makefile[PATH_MAX], git[PATH_MAX];
    int mn = snprintf(makefile, sizeof(makefile), "%s/Makefile", out);
    int gn = snprintf(git, sizeof(git), "%s/.git", out);
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    bool makefile_ok = mn > 0 && (size_t)mn < sizeof(makefile) &&
        platform_positioned_file_open(&file, makefile);
    platform_positioned_file_close(&file);
    platform_positioned_file_init(&file);
    bool git_ok = gn > 0 && (size_t)gn < sizeof(git) &&
        (platform_directory_probe_real(git) == PLATFORM_DIRECTORY_PROBE_OK ||
         platform_positioned_file_open(&file, git));
    platform_positioned_file_close(&file);
    return makefile_ok && git_ok;
}

static bool lower_hex64(const char *input, char out[65])
{
    if (!input || strlen(input) != 64)
        return false;
    for (size_t i = 0; i < 64; i++) {
        if (!isxdigit((unsigned char)input[i]))
            return false;
        out[i] = (char)tolower((unsigned char)input[i]);
    }
    out[64] = 0;
    return true;
}

static void sha3_hex(const unsigned char digest[32], char out[65])
{
    zcl_hex_encode(digest, 32, out);
}

/* Resolve the exact Make-owned dev compile epoch without executing a compiler
 * or test.  It binds source+ABA, compiler/search roots, flags/profile, and
 * link inputs; SHA3 domain separation additionally binds this lookup to the
 * compile rung of the fixed `make ff` proof. */
static bool failure_source_record_arg(
    const struct dev_source_record *source, char out[160],
    char *why, size_t why_len)
{
    int n = snprintf(out, 160, "BUILD_SOURCE_RECORD=%s 1 %s",
                     source->source_id, source->mutation_id);
    if (n <= 0 || n >= 160) {
        (void)snprintf(why, why_len, "failure_execution_record_invalid");
        return false;
    }
    return true;
}

static bool failure_execution_id(const char *root,
                                 const struct dev_source_record *source,
                                 char out[65], char *why, size_t why_len)
{
    char record[160], record_env[192], tool[PATH_MAX];
    if (!failure_source_record_arg(source, record, why, why_len))
        return false;
    const char *value = strchr(record, '=');
    int en = value ? snprintf(record_env, sizeof(record_env),
                              "ZCL_FAST_BUILD_SOURCE_RECORD=%s", value + 1)
                   : -1;
    int tn = snprintf(tool, sizeof(tool), "%s/tools/agent_fast_ci.sh", root);
    if (en <= 0 || (size_t)en >= sizeof(record_env) || tn <= 0 ||
        (size_t)tn >= sizeof(tool)) {
        (void)snprintf(why, why_len, "failure_execution_tool_path_invalid");
        return false;
    }
    /* Use the same compiler-selection path as the actual ff ladder. This binds
     * explicit ZCL_FAST_CC plus automatic ccache/sccache selection instead of
     * probing Make's unrelated default CC. */
    const char *argv[] = { "env", record_env, tool,
                           "failure-execution-id", NULL };
    struct zcl_devloop_process_result r = {0};
    if (!zcl_devloop_process_run(root, argv, 120000, &r) || !result_ok(&r) ||
        r.output_truncated) {
        (void)snprintf(why, why_len, "failure_execution_identity_failed");
        return false;
    }
    size_t len = r.output_len;
    while (len > 0 && (r.output[len - 1] == '\n' ||
                       r.output[len - 1] == '\r'))
        len--;
    char epoch[65];
    if (len != 64) {
        (void)snprintf(why, why_len, "failure_execution_identity_invalid");
        return false;
    }
    char raw[65];
    memcpy(raw, r.output, 64);
    raw[64] = 0;
    if (!lower_hex64(raw, epoch)) {
        (void)snprintf(why, why_len, "failure_execution_identity_invalid");
        return false;
    }
    static const char domain[] = "zcl.dev_failure_execution.v1";
    static const char proof[] = "make_ff_compile";
    struct sha3_256_ctx ctx;
    unsigned char digest[32];
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)domain, sizeof(domain) - 1);
    sha3_256_write(&ctx, (const unsigned char *)epoch, strlen(epoch));
    sha3_256_write(&ctx, (const unsigned char *)proof, sizeof(proof) - 1);
    sha3_256_finalize(&ctx, digest);
    sha3_hex(digest, out);
    return true;
}

static bool find_artifact(const char *root, const char *output,
                          char artifact[PATH_MAX])
{
    if (!root || !output)
        return false;
    const char *end = output + strlen(output);
    while (end > output) {
        while (end > output && (end[-1] == '\n' || end[-1] == '\r'))
            end--;
        const char *start = end;
        while (start > output && start[-1] != '\n' && start[-1] != '\r')
            start--;
        size_t len = (size_t)(end - start);
        if (len > 3 && len < PATH_MAX &&
            memchr(start, ' ', len) == NULL &&
            memchr(start, '\t', len) == NULL &&
            memcmp(end - 3, ".so", 3) == 0) {
            char candidate[PATH_MAX];
            if (start[0] == '/')
                snprintf(candidate, sizeof(candidate), "%.*s", (int)len, start);
            else
                snprintf(candidate, sizeof(candidate), "%s/%.*s",
                         root, (int)len, start);
            struct platform_positioned_file file;
            platform_positioned_file_init(&file);
            bool resolved = platform_positioned_file_open(&file, candidate) &&
                platform_positioned_file_path(&file, artifact, PATH_MAX);
            platform_positioned_file_close(&file);
            if (resolved) {
                char expected[PATH_MAX];
                snprintf(expected, sizeof(expected), "%s/build/hotswap/", root);
                return strncmp(artifact, expected, strlen(expected)) == 0;
            }
        }
        end = start;
    }
    return false;
}

static bool build_hotswap_args(const char *artifact, const char *probe,
                               char out[PATH_MAX + 256])
{
    if (!artifact || strchr(artifact, '"') || strchr(artifact, '\\') ||
        !probe ||
        strspn(probe,
               "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.") !=
            strlen(probe))
        return false;
    int n = snprintf(out, PATH_MAX + 256,
                     "--input={\"so_path\":\"%s\",\"probe_leaf\":\"%s\"}",
                     artifact, probe);
    return n > 0 && n < PATH_MAX + 256;
}

/* Extract the value of a top-level `"field":"<64 hex chars>"` member from a
 * JSON blob without pulling in a full parser — matches the string-scan idiom
 * this file already uses (see the `strstr(result.output, ...)` checks
 * above). Returns false (leaving out[0]=0) if the field is absent or is not
 * exactly 64 hex characters. */
static bool extract_hex64_field(const char *json, const char *field,
                                char out[65])
{
    out[0] = 0;
    if (!json || !field)
        return false;
    char key[96];
    int kn = snprintf(key, sizeof(key), "\"%s\"", field);
    if (kn <= 0 || (size_t)kn >= sizeof(key))
        return false;
    const char *p = strstr(json, key);
    if (!p)
        return false;
    p = strchr(p + strlen(key), '"');
    if (!p)
        return false;
    p++;
    const char *end = strchr(p, '"');
    if (!end || (size_t)(end - p) != 64)
        return false;
    memcpy(out, p, 64);
    out[64] = 0;
    return true;
}

/* Best-effort generation-id lookup for a RELOAD (transactional_reload)
 * cycle: `make agent-deploy-fast` drives tools/dev/deploy-dev-lane.sh, which
 * writes the zcl.agent_dev_deploy.v1 state file at
 * $HOME/.zclassic-c23-dev/agent-deploy.json on every activation attempt.
 * candidate_sha256 is a bare 64-hex sha256 of the built binary;
 * running_generation is "gen-<64 hex>" or "legacy-<64 hex>" once activation
 * verifies the running process matches. Absence of HOME, the file, or
 * either field is not an error here — the cycle still anchors, just with an
 * all-zero generation binding (finish_cycle passes NULL onward). */
static bool read_reload_generation(char out[65])
{
    out[0] = 0;
    const char *home = getenv("HOME");
    if (!home || !home[0])
        return false;
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path),
                     "%s/.zclassic-c23-dev/agent-deploy.json", home);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    char buf[8192];
    size_t rn = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[rn] = 0;

    if (extract_hex64_field(buf, "candidate_sha256", out))
        return true;

    /* running_generation carries a "gen-"/"legacy-" prefix, so it never
     * matches extract_hex64_field's bare-64-hex expectation directly; strip
     * the prefix by hand before comparing lengths. */
    const char *key = "\"running_generation\"";
    const char *p = strstr(buf, key);
    if (!p)
        return false;
    p = strchr(p + strlen(key), '"');
    if (!p)
        return false;
    p++;
    const char *end = strchr(p, '"');
    if (!end)
        return false;
    if ((size_t)(end - p) > 4 && memcmp(p, "gen-", 4) == 0)
        p += 4;
    else if ((size_t)(end - p) > 7 && memcmp(p, "legacy-", 7) == 0)
        p += 7;
    if ((size_t)(end - p) != 64)
        return false;
    memcpy(out, p, 64);
    out[64] = 0;
    return true;
}

#endif

/* ── Wave 3.2 native activation engine — dev-lane wiring (pure glue) ────
 * These three functions are declared in devloop.h; the guard there matches
 * this one (ZCL_DEV_BUILD || ZCL_TESTING) so the hermetic test harness can
 * exercise them directly without a fake ops vtable — none of them execs a
 * process or performs I/O beyond getenv(). The actual engine call
 * (dev_activation_run / dev_activation_default_ops, both real-process-exec)
 * stays confined to the ZCL_DEV_BUILD-only zcl_devloop_run_cycle_mode() body
 * below. */
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
bool dev_activation_native_enabled(void)
{
    const char *v = getenv("ZCL_DEV_NATIVE_ACTIVATION");
    if (!v || !v[0])
        return false;
    return strcmp(v, "1") == 0 || strcmp(v, "true") == 0 ||
           strcmp(v, "yes") == 0;
}

bool dev_activation_request_from_cycle(const char *repo_root,
                                       const char *build_commit,
                                       struct dev_activation_cycle_request *out)
{
    if (!repo_root || !repo_root[0] || !build_commit || !out)
        return false;
    const char *home = getenv("HOME");
    if (!home || !home[0])
        return false;

    int n = snprintf(out->artifact_path, sizeof(out->artifact_path),
                     "%s/build/bin/zclassic23-dev", repo_root);
    if (n <= 0 || (size_t)n >= sizeof(out->artifact_path))
        return false;

    const char *gen_root_override = getenv("ZCL_DEV_GENERATION_ROOT");
    n = (gen_root_override && gen_root_override[0])
            ? snprintf(out->gen_root, sizeof(out->gen_root), "%s",
                      gen_root_override)
            : snprintf(out->gen_root, sizeof(out->gen_root),
                      "%s/.local/lib/zclassic23-dev", home);
    if (n <= 0 || (size_t)n >= sizeof(out->gen_root))
        return false;

    n = snprintf(out->datadir, sizeof(out->datadir), "%s/.zclassic-c23-dev",
                home);
    if (n <= 0 || (size_t)n >= sizeof(out->datadir))
        return false;

    memset(&out->req, 0, sizeof(out->req));
    out->req.repo_root = repo_root;
    out->req.artifact_path = out->artifact_path;
    out->req.build_commit = build_commit;
    out->req.build_type = "fast";
    out->req.source_mutation = NULL;
    out->req.expected_current_generation = NULL;
    out->req.gen_root = out->gen_root;
    out->req.datadir = out->datadir;
    out->req.unit = "zcl23-dev.service";
    out->req.rpcport = 18252;
    out->req.mode = DEV_ACTIVATION_MODE_ACTIVATE;
    return true;
}

void dev_activation_map_result(const struct dev_activation_result *r,
                               struct dev_activation_cycle_outcome *out)
{
    memset(out, 0, sizeof(*out));
    if (!r)
        return;
    out->ok = (r->status == DEV_ACTIVATION_OK);
    const char *capsule = r->failure_capsule[0] ? r->failure_capsule
                          : r->verify_detail[0] ? r->verify_detail : "";
    snprintf(out->capsule, sizeof(out->capsule), "%s", capsule);
    snprintf(out->generation_hex, sizeof(out->generation_hex), "%s",
            r->candidate_sha256);
}
#endif /* ZCL_DEV_BUILD || ZCL_TESTING */

int zcl_devloop_run_sim(const char *repo_root)
{
#ifndef ZCL_DEV_BUILD
    (void)repo_root;
    fprintf(stderr, "[devloop] simulator execution requires ZCL_DEV_BUILD\n");
    return 2;
#else
    char root[PATH_MAX], test_bin[PATH_MAX];
    if (!repo_root_resolve(repo_root, root)) {
        fprintf(stderr, "[devloop] simulator: invalid repository root\n");
        return 2;
    }
    snprintf(test_bin, sizeof(test_bin), "%s/build/bin/test_parallel_fast", root);
    if (access(test_bin, X_OK) != 0) {
        fprintf(stderr, "[devloop] simulator: focused runner is not built\n");
        return 2;
    }
    const char *argv[] = { test_bin, "--only=hotswap_simnet", NULL };
    struct zcl_devloop_process_result result = {0};
    if (!zcl_devloop_process_run(root, argv, 10000, &result))
        return 1;
    if (!result_ok(&result)) {
        char capsule[1024];
        output_capsule(&result, capsule);
        fprintf(stderr, "[devloop] simulator failed: %s\n", capsule);
        return 1;
    }
    printf("{\"schema\":\"zcl.dev_sim.v1\",\"status\":\"passed\","
           "\"group\":\"hotswap_simnet\",\"elapsed_ms\":%lld}\n",
           (long long)result.elapsed_ms);
    return 0;
#endif
}

/* ZVCS auto-anchor outcome for this cycle's verdict JSON. Populated
 * unconditionally (zero-valued when the anchor was never attempted — e.g. a
 * non-"passed" verdict, or a release build), so cycle_json() needs no
 * ZCL_DEV_BUILD conditional of its own. */
struct vcs_anchor_fields {
    bool attempted;
    char commit_hex[65];  /* set iff the snapshot committed */
    char error[256];      /* set iff attempted and not committed */
    bool sealed_refusal;  /* true iff refused for touching a sealed path */
    bool deferred;        /* generation-neutral first baseline is out of band */
    enum vcs_devloop_publication_status publication_status;
    char proof_receipt_hex[65];
    char publication_job_hex[65];
    int64_t publication_enqueue_us;
    bool publication_reused;
    char publication_error[256];
};

#define CYCLE_FILE_PREVIEW_MAX 2
#define CYCLE_FILE_PREVIEW_BYTES 160
#define CYCLE_CAPSULE_PREVIEW_BYTES 384
#define CYCLE_ERROR_PREVIEW_BYTES 256

static void cycle_files_sha3(const char *const *files, size_t file_count,
                             char out[65])
{
    static const unsigned char domain[] = "zcl.dev_cycle_files.v1";
    const unsigned char zero = 0;
    char count[32];
    (void)snprintf(count, sizeof(count), "%zu", file_count);
    struct sha3_256_ctx ctx;
    unsigned char digest[32];
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, domain, sizeof(domain) - 1);
    sha3_256_write(&ctx, &zero, 1);
    sha3_256_write(&ctx, (const unsigned char *)count, strlen(count));
    sha3_256_write(&ctx, &zero, 1);
    for (size_t i = 0; i < file_count; i++) {
        const char *path = files[i] ? files[i] : "";
        sha3_256_write(&ctx, (const unsigned char *)path, strlen(path));
        sha3_256_write(&ctx, &zero, 1);
    }
    sha3_256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
}

static bool cycle_text_preview(const char *input, size_t max_bytes,
                               char *out, size_t out_len,
                               bool *truncated_out)
{
    if (!input || !out || out_len == 0 || max_bytes + 1 > out_len)
        return false;
    size_t pos = 0;
    bool truncated = false;
    const unsigned char *p = (const unsigned char *)input;
    while (*p) {
        if (pos >= max_bytes) {
            truncated = true;
            break;
        }
        unsigned char c = *p++;
        out[pos++] = c >= 0x20 && c < 0x7f ? (char)c : '?';
    }
    out[pos] = 0;
    if (truncated_out)
        *truncated_out = truncated;
    return true;
}

bool zcl_devloop_cycle_proof_complete(const char *status, const char *phase)
{
    return status && phase && strcmp(status, "passed") == 0 &&
           strcmp(phase, "verify") == 0;
}

static size_t cycle_json(const struct zcl_devloop_plan *plan,
                         const char *const *files, size_t file_count,
                         const char *status, const char *phase,
                         int64_t elapsed_ms, const char *capsule,
                         const struct vcs_anchor_fields *vcs,
                         char *out, size_t out_sz)
{
    size_t pos = 0;
    char files_digest[65];
    char capsule_preview[CYCLE_CAPSULE_PREVIEW_BYTES + 1];
    bool capsule_truncated = false;
    bool proof_complete =
        zcl_devloop_cycle_proof_complete(status, phase);
    cycle_files_sha3(files, file_count, files_digest);
    if (!cycle_text_preview(capsule ? capsule : "",
                            CYCLE_CAPSULE_PREVIEW_BYTES,
                            capsule_preview, sizeof(capsule_preview),
                            &capsule_truncated))
        return 0;
    if (!appendf(out, out_sz, &pos,
                 "{\"schema\":\"zcl.dev_cycle.v1\",\"producer\":\"native\",\"status\":") ||
        !append_string(out, out_sz, &pos, status) ||
        !appendf(out, out_sz, &pos, ",\"action\":") ||
        !append_string(out, out_sz, &pos, plan->action_name) ||
        !appendf(out, out_sz, &pos, ",\"reason\":") ||
        !append_string(out, out_sz, &pos, plan->reason) ||
        !appendf(out, out_sz, &pos, ",\"phase\":") ||
        !append_string(out, out_sz, &pos, phase) ||
        !appendf(out, out_sz, &pos,
                 ",\"runtime_published\":%s,\"proof_complete\":%s,"
                 "\"proof_scope\":\"%s\","
                 "\"proof_reuse_scope\":\"%s\",\"elapsed_ms\":%lld,"
                 "\"file_count\":%zu,\"files_sha3\":\"%s\",\"files\":[",
                 strcmp(status, "passed") == 0 &&
                         (strcmp(phase, "resident_commit") == 0 ||
                          strcmp(phase, "transactional_reload") == 0)
                     ? "true" : "false",
                 proof_complete ? "true" : "false",
                 proof_complete
                     ? "source_wide_compile_tests_lint_fast" : "none",
                 proof_complete ? "exact_source_id_sha256" : "none",
                 (long long)elapsed_ms, file_count, files_digest))
        return 0;
    size_t preview_count = file_count < CYCLE_FILE_PREVIEW_MAX
                               ? file_count : CYCLE_FILE_PREVIEW_MAX;
    bool files_truncated = preview_count < file_count;
    for (size_t i = 0; i < preview_count; i++) {
        char path_preview[CYCLE_FILE_PREVIEW_BYTES + 1];
        bool path_truncated = false;
        if (!cycle_text_preview(files[i] ? files[i] : "",
                                CYCLE_FILE_PREVIEW_BYTES, path_preview,
                                sizeof(path_preview), &path_truncated))
            return 0;
        files_truncated = files_truncated || path_truncated;
        if ((i && !appendf(out, out_sz, &pos, ",")) ||
            !append_string(out, out_sz, &pos, path_preview))
            return 0;
    }
    if (!appendf(out, out_sz, &pos,
                 "],\"files_truncated\":%s,\"failure_capsule\":",
                 files_truncated ? "true" : "false") ||
        !append_string(out, out_sz, &pos, capsule_preview) ||
        (capsule_truncated &&
         !appendf(out, out_sz, &pos, ",\"failure_capsule_truncated\":true")) ||
        !appendf(out, out_sz, &pos, ",\"why_not_live\":") ||
        !append_string(out, out_sz, &pos,
                       strcmp(status, "passed") == 0
                           ? ""
                           : (capsule_preview[0] ? capsule_preview
                                                 : plan->reason)) ||
        !appendf(out, out_sz, &pos, ",\"agent_next_action\":") ||
        !append_string(
            out, out_sz, &pos,
#ifdef ZCL_DEV_BUILD
            g_cycle_failure.failure_id[0]
                ? "z23-dev dev diagnose show <failure_id>"
                :
#endif
            strcmp(status, "passed") != 0
                ? "inspect this cycle's failure capsule; no durable compiler failure ID was issued"
                : proof_complete
                    ? "edit code; this exact source epoch already has complete compile, source-wide test, and lint-fast proof"
                    : strcmp(plan->action_name, "verify") == 0
                        ? "verification finished without reusable complete proof; inspect proof_complete and phase"
                    : "keep editing; native watch owns the next cycle"))
        return 0;
#ifdef ZCL_DEV_BUILD
    if (g_cycle_failure.source_ready &&
        (!appendf(out, out_sz, &pos, ",\"source_id_sha256\":") ||
         !append_string(out, out_sz, &pos,
                        g_cycle_failure.source.source_id) ||
         !appendf(out, out_sz, &pos, ",\"source_mutation_sha256\":") ||
         !append_string(out, out_sz, &pos,
                        g_cycle_failure.source.mutation_id)))
        return 0;
    if (g_cycle_failure.execution_ready &&
        (!appendf(out, out_sz, &pos, ",\"execution_id_sha3\":") ||
         !append_string(out, out_sz, &pos,
                        g_cycle_failure.execution_id)))
        return 0;
    if (g_cycle_failure.failure_id[0]) {
        char first_error_preview[CYCLE_ERROR_PREVIEW_BYTES + 1];
        bool first_error_truncated = false;
        if (!cycle_text_preview(g_cycle_failure.first_error,
                                CYCLE_ERROR_PREVIEW_BYTES,
                                first_error_preview,
                                sizeof(first_error_preview),
                                &first_error_truncated))
            return 0;
        if (!appendf(out, out_sz, &pos, ",\"failure_id\":") ||
            !append_string(out, out_sz, &pos,
                           g_cycle_failure.failure_id) ||
            !appendf(out, out_sz, &pos, ",\"failure_phase\":") ||
            !append_string(out, out_sz, &pos,
                           g_cycle_failure.failure_phase) ||
            !appendf(out, out_sz, &pos, ",\"first_error\":") ||
            !append_string(out, out_sz, &pos, first_error_preview) ||
            (first_error_truncated &&
             !appendf(out, out_sz, &pos,
                      ",\"first_error_truncated\":true")) ||
            !appendf(out, out_sz, &pos,
                     ",\"repeat_count\":%llu,\"coalesced\":%s,"
                     "\"next\":[{\"command\":\"dev.diagnose.show\","
                     "\"input\":{\"failure_id\":",
                     (unsigned long long)g_cycle_failure.repeat_count,
                     g_cycle_failure.coalesced ? "true" : "false") ||
            !append_string(out, out_sz, &pos,
                           g_cycle_failure.failure_id) ||
            !appendf(out, out_sz, &pos,
                     "},\"reason\":\"read the durable failure once; edit "
                     "source to retry automatically or run dev.ff for an "
                     "explicit unchanged retry\"}]"))
            return 0;
    }
    if (g_cycle_failure.store_error[0] &&
        (!appendf(out, out_sz, &pos, ",\"failure_store_error\":") ||
         !append_string(out, out_sz, &pos,
                        g_cycle_failure.store_error)))
        return 0;
#endif
    if (vcs && vcs->attempted) {
        if (vcs->commit_hex[0] &&
            (!appendf(out, out_sz, &pos, ",\"vcs_commit\":") ||
             !append_string(out, out_sz, &pos, vcs->commit_hex)))
            return 0;
        if (vcs->error[0] &&
            (!appendf(out, out_sz, &pos, ",\"vcs_error\":") ||
             !append_string(out, out_sz, &pos, vcs->error)))
            return 0;
        if (vcs->sealed_refusal &&
            !appendf(out, out_sz, &pos, ",\"vcs_sealed_refusal\":true"))
            return 0;
        if (vcs->deferred &&
            !appendf(out, out_sz, &pos, ",\"vcs_deferred\":true"))
            return 0;
        const char *publication_status =
            vcs->publication_status == VCS_DEVLOOP_PUBLICATION_QUEUED
                ? "QUEUED"
                : vcs->publication_status == VCS_DEVLOOP_PUBLICATION_ERROR
                    ? "ERROR" : "NOT_ELIGIBLE";
        if (!appendf(out, out_sz, &pos, ",\"publication_status\":") ||
            !append_string(out, out_sz, &pos, publication_status))
            return 0;
        if (vcs->proof_receipt_hex[0] &&
            (!appendf(out, out_sz, &pos, ",\"proof_receipt_root\":") ||
             !append_string(out, out_sz, &pos,
                            vcs->proof_receipt_hex)))
            return 0;
        if (vcs->publication_job_hex[0] &&
            vcs->publication_status == VCS_DEVLOOP_PUBLICATION_QUEUED) {
            char next_command[256];
            int next_len = snprintf(
                next_command, sizeof(next_command),
                "z23-dev dev publication status --input='"
                "{\"job_root\":\"%s\"}'",
                vcs->publication_job_hex);
            if (next_len <= 0 || (size_t)next_len >= sizeof(next_command) ||
                !appendf(out, out_sz, &pos,
                         ",\"publication_job_root\":") ||
                !append_string(out, out_sz, &pos,
                               vcs->publication_job_hex) ||
                !appendf(out, out_sz, &pos,
                         ",\"publication_enqueue_us\":%lld,"
                         "\"publication_reused\":%s,"
                         "\"publication_next_command\":",
                         (long long)vcs->publication_enqueue_us,
                         vcs->publication_reused ? "true" : "false") ||
                !append_string(out, out_sz, &pos, next_command))
                return 0;
        }
        if (vcs->publication_error[0] &&
            (!appendf(out, out_sz, &pos, ",\"publication_error\":") ||
             !append_string(out, out_sz, &pos,
                            vcs->publication_error)))
            return 0;
    }
    if (!appendf(out, out_sz, &pos, "}"))
        return 0;
    return pos;
}

static int finish_cycle(const struct zcl_devloop_plan *plan,
                        const char *const *files, size_t file_count,
                        const char *status, const char *phase,
                        int64_t started_us, const char *capsule,
                        const char *repo_root, const char *generation_hex)
{
    const char *event_phase = strcmp(status, "superseded") == 0
        ? zcl_devloop_progress_phase(status, phase) : phase;
    /* A watcher saw a newer source epoch while this synchronous cycle was in
     * flight. It owns the replacement batch; never publish this stale result
     * or anchor its superseded bytes. */
    if (zcl_devloop_process_cancel_requested()) {
#ifdef ZCL_DEV_BUILD
        cycle_failure_reset();
#endif
        return 4;
    }
    char body[16384];
    int64_t elapsed_ms = (platform_time_monotonic_us() - started_us) / 1000;

#ifdef ZCL_DEV_BUILD
    /* Persist only an allowlisted deterministic red.  Store failure never
     * changes the proof verdict: an unavailable/corrupt diagnostic store is
     * named in the cycle and the next wake executes again (safe miss). */
    if (strcmp(status, "passed") != 0 && g_cycle_failure.cacheable &&
        !g_cycle_failure.failure_id[0] && g_cycle_failure.source_ready &&
        g_cycle_failure.execution_ready && repo_root && repo_root[0]) {
        struct zcl_dev_failure_record record;
        char why[sizeof(g_cycle_failure.store_error)] = {0};
        if (zcl_dev_failure_record_failure(
                repo_root, g_cycle_failure.source.source_id,
                g_cycle_failure.source.mutation_id,
                g_cycle_failure.execution_id,
                g_cycle_failure.failure_phase,
                g_cycle_failure.first_error, capsule ? capsule : "",
                "dev.ff", &record, why, sizeof(why))) {
            (void)snprintf(g_cycle_failure.failure_id,
                           sizeof(g_cycle_failure.failure_id), "%s",
                           record.failure_id);
            g_cycle_failure.repeat_count = record.repeat_count;
        } else {
            (void)snprintf(g_cycle_failure.store_error,
                           sizeof(g_cycle_failure.store_error), "%s",
                           why[0] ? why : "failure_store_write_failed");
        }
    }
#endif

    /* Auto-anchor on green (Wave 2.3): every "passed" verdict gets a ZVCS
     * snapshot binding the source tree to this verdict + the binary
     * generation it produced. Fail-open by construction: vcs_devloop never
     * uses a process-terminating LOG_* macro, so a ZVCS problem can only
     * ever change what lands in the "vcs_commit"/"vcs_error" verdict
     * fields below, never the cycle's own pass/fail outcome. */
    struct vcs_anchor_fields vcsf = {0};
#ifdef ZCL_DEV_BUILD
    if (strcmp(status, "passed") == 0 && repo_root && repo_root[0]) {
        struct vcs_devloop_verdict v = {0};
        v.verdict_status = 0;
        v.phase = phase;
        v.elapsed_ms = elapsed_ms;
        v.generation_hex = (generation_hex && generation_hex[0]) ? generation_hex : NULL;
        v.agent_id = getenv("ZCL_AGENT_ID");
        v.session_id = getenv("ZCL_SESSION_ID");
        v.task_ref = getenv("ZCL_TASK_REF");
        v.defer_initial_snapshot = true;
        v.proof_complete =
            zcl_devloop_cycle_proof_complete(status, phase);
        v.proof_scope = v.proof_complete
            ? "source_wide_compile_tests_lint_fast" : NULL;
        v.source_identity_hex = g_cycle_failure.source_ready
            ? g_cycle_failure.source.source_id : NULL;
        v.source_cas_hex = g_cycle_failure.source_ready &&
                g_cycle_failure.source.cas_present
            ? g_cycle_failure.source.cas_root_sha3 : NULL;

        struct vcs_devloop_anchor_result ar;
        vcs_devloop_anchor_cycle(repo_root, &v, &ar);
        vcsf.attempted = true;
        switch (ar.status) {
        case VCS_DEVLOOP_ANCHOR_OK:
            zcl_hex_encode(ar.commit_id, 32, vcsf.commit_hex);
            vcsf.publication_status = ar.publication_status;
            vcsf.publication_enqueue_us = ar.publication_enqueue_us;
            vcsf.publication_reused = ar.publication_reused;
            if (ar.publication_status == VCS_DEVLOOP_PUBLICATION_QUEUED) {
                zcl_hex_encode(ar.proof_receipt_root, 32,
                               vcsf.proof_receipt_hex);
                zcl_hex_encode(ar.publication_job_root, 32,
                               vcsf.publication_job_hex);
            }
            (void)snprintf(vcsf.publication_error,
                           sizeof(vcsf.publication_error), "%s",
                           ar.publication_error);
            break;
        case VCS_DEVLOOP_ANCHOR_REFUSED:
            vcsf.sealed_refusal = true;
            snprintf(vcsf.error, sizeof(vcsf.error), "%s", ar.error);
            break;
        case VCS_DEVLOOP_ANCHOR_DEFERRED:
            vcsf.deferred = true;
            snprintf(vcsf.error, sizeof(vcsf.error), "%s", ar.error);
            /* lib/vcs never launches the baseline itself (ZVCS
             * sovereignty — check-vcs-no-git). When this cycle is the one
             * that discovered no baseline is running yet, the dev loop is
             * responsible for detaching it so the baseline's first-snapshot
             * cost doesn't block the edit->verdict latency path. */
            if (ar.baseline_needed &&
                !zcl_devloop_baseline_launch(repo_root))
                fprintf(stderr,
                        "[devloop] vcs baseline detach failed (fail-open): "
                        "will retry next cycle\n");
            break;
        case VCS_DEVLOOP_ANCHOR_ERROR:
        default:
            snprintf(vcsf.error, sizeof(vcsf.error), "%s", ar.error);
            fprintf(stderr, "[devloop] vcs auto-anchor failed (fail-open): %s\n",
                    ar.error);
            break;
        }
    }
#else
    (void)repo_root;
    (void)generation_hex;
#endif

    size_t len = cycle_json(plan, files, file_count, status, event_phase,
                            elapsed_ms, capsule, &vcsf, body,
                            sizeof(body) - 2);
    if (len == 0) {
        fprintf(stderr, "[devloop] cycle verdict exceeded its bounded buffer\n");
#ifdef ZCL_DEV_BUILD
        cycle_failure_reset();
#endif
        return 1;
    }
    body[len++] = '\n';
    body[len] = 0;
    char state_why[160] = {0};
    bool state_persisted = true;
    if (repo_root && repo_root[0])
        state_persisted = zcl_devloop_cycle_state_write(
            repo_root, body, len, state_why, sizeof(state_why));
    if (!state_persisted) {
        fprintf(stderr,
                "[devloop] could not persist native cycle verdict: %s\n",
                state_why[0] ? state_why : "unknown");
        /* Never print a passing current-cycle claim when durable publication
         * failed and dev.status would still expose the prior generation. */
        size_t pos = 0;
        if (!appendf(body, sizeof(body) - 2, &pos,
                     "{\"schema\":\"zcl.dev_cycle.v1\","
                     "\"producer\":\"native\",\"status\":\"rejected\","
                     "\"action\":\"verify\","
                     "\"reason\":\"cycle_state_publication_failed\","
                     "\"phase\":\"state_publish\","
                     "\"runtime_published\":false,"
                     "\"state_persisted\":false,\"failure_capsule\":") ||
            !append_string(body, sizeof(body) - 2, &pos,
                           state_why[0] ? state_why : "unknown") ||
            !appendf(body, sizeof(body) - 2, &pos,
                     ",\"why_not_live\":") ||
            !append_string(body, sizeof(body) - 2, &pos,
                           state_why[0] ? state_why : "unknown") ||
            !appendf(body, sizeof(body) - 2, &pos,
                     ",\"agent_next_action\":"
                     "\"repair workspace state storage and rerun the cycle\"}")) {
            fprintf(stderr, "[devloop] state failure envelope overflow\n");
            pos = 0;
        }
        if (pos > 0) {
            body[pos++] = '\n';
            body[pos] = 0;
            len = pos;
        }
    }
    fwrite(body, 1, len, stdout);
    fflush(stdout);
    int rc = state_persisted && strcmp(status, "passed") == 0 ? 0 : 1;
#ifdef ZCL_DEV_BUILD
    cycle_failure_reset();
#endif
    return rc;
}

/* Wave 2.4 core refusal: emit the structured sealed-core refusal envelope
 * (stdout + the persisted zcl.dev_cycle.v1 verdict) and return CLI exit 3
 * (blocked-by-precondition). Reused by both the one-shot `dev change cycle`
 * path and the persistent watcher — both funnel through
 * zcl_devloop_run_cycle(). No subprocess is launched: the caller returns here
 * BEFORE any hotswap/reload publish step. */
static int emit_refusal(const char *repo_root, const char *const *files,
                        size_t file_count)
{
    char body[16384];
    size_t len = zcl_devloop_refusal_json(files, file_count, body,
                                          sizeof(body) - 2);
    if (len == 0) {
        fprintf(stderr,
                "[devloop] sealed-core refusal envelope exceeded its buffer\n");
        return 3;  /* still refuse — never fall through to publish */
    }
    body[len++] = '\n';
    body[len] = 0;
    char state_why[160] = {0};
    if (repo_root && repo_root[0] &&
        !zcl_devloop_cycle_state_write(repo_root, body, len, state_why,
                                       sizeof(state_why)))
        fprintf(stderr, "[devloop] could not persist refusal verdict: %s\n",
                state_why[0] ? state_why : "unknown");
    fwrite(body, 1, len, stdout);
    fflush(stdout);
    return 3;
}

bool zcl_devloop_publish_mode_applies(
    enum zcl_devloop_publish_mode publish_mode)
{
    return publish_mode == ZCL_DEVLOOP_PUBLISH_APPLY;
}

const char *zcl_devloop_publish_mode_name(
    enum zcl_devloop_publish_mode publish_mode)
{
    switch (publish_mode) {
    case ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY:
        return "verify";
    case ZCL_DEVLOOP_PUBLISH_APPLY:
        return "auto";
    }
    return NULL;
}

enum zcl_devloop_publish_mode zcl_devloop_default_watch_publish_mode(void)
{
    return ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY;
}

bool zcl_devloop_publication_target_port_supported(int rpc_port)
{
    return rpc_port == 18252;
}

const char *zcl_devloop_watcher_freshness(bool active, bool source_ready,
                                          bool runtime_ready)
{
    if (!active)
        return "watcher_not_running";
    if (!source_ready)
        return "watcher_starting";
    return runtime_ready ? "current" : "runtime_starting";
}

const char *zcl_devloop_watcher_next_action(
    bool active, bool source_ready, bool runtime_ready,
    enum zcl_devloop_publish_mode publish_mode)
{
    if (!active)
        return "z23-dev dev begin";
    if (!source_ready)
        return "z23-dev dev loop status";
    if (zcl_devloop_publish_mode_applies(publish_mode) && !runtime_ready)
        return "start or wait for the isolated dev node on RPC 18252, then "
               "rerun z23-dev dev loop status";
    return "edit one C23 file";
}

int zcl_devloop_run_cycle_mode(const char *repo_root,
                               const char *const *files,
                               size_t file_count,
                               enum zcl_devloop_publish_mode publish_mode)
{
    struct zcl_devloop_plan plan;
    int64_t started_us = platform_time_monotonic_us();
#ifdef ZCL_DEV_BUILD
    cycle_failure_reset();
#endif
    if (!zcl_devloop_publish_mode_name(publish_mode)) {
        fprintf(stderr, "[devloop] cycle: invalid publication mode\n");
        return 2;
    }
    if ((file_count > 0 && !files) || file_count > ZCL_DEVLOOP_MAX_FILES) {
        fprintf(stderr, "[devloop] cycle: invalid changed-file set\n");
        return 2;
    }
    /* Caller paths are bounded wake hints. They may only add restrictions
     * (for example, an explicit sealed-Core refusal); they never reduce the
     * proof selected for a changed source epoch. */
    if (!zcl_devloop_plan_files(files, file_count, &plan)) {
        fprintf(stderr, "[devloop] cycle: invalid changed-file set\n");
        return 2;
    }
#ifdef ZCL_DEV_BUILD
    char root[PATH_MAX] = {0};
    struct dev_source_record expected_source = {0};
    if (!repo_root_resolve(repo_root, root))
        return finish_cycle(&plan, files, file_count, "rejected",
                            "source_identity", started_us,
                            "repository root is not a real Git checkout",
                            NULL, NULL);
    char source_why[512] = {0};
    if (!zcl_dev_source_identity_capture(root, &expected_source,
                                 source_why, sizeof(source_why)))
        return finish_cycle(&plan, files, file_count, "rejected",
                            "source_identity", started_us,
                            source_why[0] ? source_why
                                          : "source identity capture failed",
                            root, NULL);
    g_cycle_failure.source = expected_source;
    g_cycle_failure.source_ready = true;
    if (file_count > 0) {
        /* No HEAD-relative dirty set participates in proof authority. Until a
         * signed prior source epoch can produce an authenticated content diff,
         * every changed source epoch takes the conservative reload/parity
         * lane. Wake hints can never downgrade this decision to docs-only or
         * hot-swap. APPLY remains hard-contained below. */
        plan.action = ZCL_DEVLOOP_RELOAD;
        plan.action_name = "reload";
        plan.reason = "source_epoch_requires_conservative_full_proof";
        plan.probe_tool = "";
        snprintf(plan.proof_group_storage,
                 sizeof(plan.proof_group_storage), "consensus_parity");
        plan.proof_group = plan.proof_group_storage;
        plan.consensus_risk = true;
        plan.docs_only = false;
    }
#endif
    /* Phase-0 containment: no caller-selected mode is publication authority.
     * Keep complete-source classification, builds, proofs, and candidate
     * probes available in VERIFY_ONLY, but refuse APPLY before compilation,
     * dlopen, service control, or generation relinking.  This remains closed
     * until immutable source epochs, complete proof receipts, a resident
     * expected-epoch CAS, durable accept/rollback receipts, and signed seal
     * authority are one transaction. */
    if (zcl_devloop_publish_mode_applies(publish_mode)) {
        plan.action_name = "apply";
        (void)finish_cycle(
            &plan, files, file_count, "blocked", "publication_contained",
            started_us,
            "runtime publication is contained until the source epoch, proof "
            "receipts, resident CAS, and rollback are durably bound",
            repo_root, NULL);
        return 3;
    }
    /* Core refusal, BEFORE any publish and BEFORE the dev-build gate (a
     * release binary refuses identically). A changed-file set touching the
     * sealed consensus core (core/ — what core/MANIFEST.sha3 pins) is
     * structurally refused from the autonomous fast path unless the owner
     * unseal ritual left a valid one-shot .core-unseal-token at the repo root.
     *
     * Token semantics (see zcl_devloop_unseal_token_present): the token is
     * checked read-only and NEVER consumed here. `make core-seal` consumes it
     * when the sealed edit lands, so one `make core-unseal` authorizes exactly
     * one landed commit — which may cover several iterative dev-cycles while
     * the author converges the fix — not one dev-cycle. With the token
     * present the cycle proceeds and (because zcl_devloop_plan_files marks any
     * sealed file consensus_risk) routes to the heaviest proof path, exactly
     * as a lib/validation edit does today. Sealed != frozen: the refusal
     * envelope always names the elevated procedure. */
    if (plan.sealed_core) {
        if (!zcl_devloop_unseal_token_present(repo_root))
            return emit_refusal(repo_root, files, file_count);
        fprintf(stderr,
                "[devloop] sealed consensus core: unseal token present at "
                "%s/.core-unseal-token — seal lifted for THIS cycle; routing "
                "to the heaviest proof path. The token is consumed by "
                "'make core-seal' when the edit lands, so one unseal = one "
                "landed commit, not one dev-cycle.\n",
                (repo_root && repo_root[0]) ? repo_root : ".");
    }
#ifndef ZCL_DEV_BUILD
    (void)repo_root;
    return finish_cycle(&plan, files, file_count, "rejected",
                        "dev_build_required", started_us,
                        "native mutation is compiled out of release builds",
                        NULL, NULL);
#else
    if (!root[0] && !repo_root_resolve(repo_root, root))
        return finish_cycle(&plan, files, file_count, "rejected",
                            "confinement", started_us,
                            "repository root is not a real zclassic23 checkout",
                            NULL, NULL);
    if (plan.action == ZCL_DEVLOOP_CHECK)
        return finish_cycle(&plan, files, file_count, "passed", "check",
                            started_us, "", root, NULL);

    struct zcl_devloop_process_result result = {0};
    char capsule[1024] = {0};
    if (plan.action == ZCL_DEVLOOP_HOTSWAP) {
        char test_bin[PATH_MAX];
        snprintf(test_bin, sizeof(test_bin), "%s/build/bin/test_parallel_fast", root);
        const char *sim_argv[] = {
            test_bin, "--only=hotswap_simnet", NULL
        };
        if (access(test_bin, X_OK) != 0 ||
            !zcl_devloop_process_run(root, sim_argv, 10000, &result) ||
            !result_ok(&result)) {
            output_capsule(&result, capsule);
            return finish_cycle(&plan, files, file_count, "rejected",
                                "sim", started_us,
                                capsule[0] ? capsule : "fast sim runner unavailable",
                                root, NULL);
        }

        char files_arg[ZCL_DEVLOOP_PATH_MAX + 16];
        snprintf(files_arg, sizeof(files_arg), "FILES=%s", files[0]);
        const char *build_argv[] = {
            "make", "--no-print-directory", "hotswap-so", files_arg, NULL
        };
        if (!zcl_devloop_process_run(root, build_argv, 60000, &result) ||
            !result_ok(&result)) {
            output_capsule(&result, capsule);
            return finish_cycle(&plan, files, file_count, "rejected",
                                "build", started_us, capsule, root, NULL);
        }
        char artifact[PATH_MAX];
        if (!find_artifact(root, result.output, artifact))
            return finish_cycle(&plan, files, file_count, "rejected",
                                "build", started_us,
                                "generation builder returned no confined artifact",
                                root, NULL);

        const char *home = getenv("HOME");
        char bin[PATH_MAX], datadir_flag[PATH_MAX], args_json[PATH_MAX + 256];
        if (!home || !home[0] ||
            snprintf(bin, sizeof(bin), "%s/build/bin/zclassic23-dev", root) <= 0 ||
            snprintf(datadir_flag, sizeof(datadir_flag),
                     "-datadir=%s/.zclassic-c23-dev", home) <= 0 ||
            !build_hotswap_args(artifact, plan.probe_tool, args_json))
            return finish_cycle(&plan, files, file_count, "rejected",
                                "confinement", started_us,
                                "could not construct exact dev-lane invocation",
                                root, NULL);

        const char *smoke_argv[] = {
            bin, datadir_flag, "-rpcport=18252", "dev", "hotswap",
            "probe", args_json, NULL
        };
        if (!zcl_devloop_process_run(root, smoke_argv, 15000, &result) ||
            !result_ok(&result) || !strstr(result.output, "\"ok\":true") ||
            strstr(result.output, "\"probe_error\"")) {
            output_capsule(&result, capsule);
            return finish_cycle(&plan, files, file_count, "rejected",
                                "precommit_probe", started_us, capsule,
                                root, NULL);
        }

        /* Watchers stop after the real candidate probe.  The resident commit
         * below is reachable only through an explicit apply/auto invocation;
         * file classification (including a consensus-risk classification)
         * can never grant publication authority. */
        if (!zcl_devloop_publish_mode_applies(publish_mode)) {
            plan.action_name = "verify";
            char source_why[256] = {0};
            if (!zcl_dev_source_identity_verify(root, &expected_source,
                                        source_why, sizeof(source_why)))
                return finish_cycle(
                    &plan, files, file_count, "superseded",
                    "source_epoch_cas", started_us,
                    source_why[0] ? source_why
                                  : "source epoch changed during candidate probe",
                    root, NULL);
            fprintf(stderr,
                    "[devloop] hot-swap candidate verified; runtime "
                    "publication remains contained\n");
            return finish_cycle(&plan, files, file_count, "passed",
                                "precommit_probe", started_us, "",
                                root, NULL);
        }

        char source_why[256] = {0};
        if (!zcl_dev_source_identity_verify(root, &expected_source,
                                    source_why, sizeof(source_why))) {
            return finish_cycle(&plan, files, file_count, "superseded",
                                "source_epoch_cas", started_us,
                                source_why[0] ? source_why
                                              : "source epoch changed before resident commit",
                                root, NULL);
        }

        const char *commit_argv[] = {
            bin, datadir_flag, "-rpcport=18252", "dev_hotswap",
            artifact, plan.probe_tool, NULL
        };
        if (!zcl_devloop_process_run(root, commit_argv, 15000, &result) ||
            !result_ok(&result) || !strstr(result.output, "\"ok\":true")) {
            if (strstr(result.output, "generation registry full") &&
                strstr(result.output, "\"rejection_stage\":\"registry\""))
                goto transactional_reload;
            output_capsule(&result, capsule);
            return finish_cycle(&plan, files, file_count, "rejected",
                                "resident_commit", started_us, capsule,
                                root, NULL);
        }
        /* The route-generation id for a hotswap cycle: dev_hotswap's JSON
         * result (same shape as the native hot-swap command's, see
         * the resident hot-swap handler already carries
         * artifact_sha256 — the sha256 of the exact .so this cycle dlopen'd.
         * Best-effort: an empty/unparsable value just means the anchor binds
         * a zero generation, never a cycle failure. */
        char generation_hex[65];
        extract_hex64_field(result.output, "artifact_sha256", generation_hex);
        return finish_cycle(&plan, files, file_count, "passed",
                            "resident_commit", started_us, "",
                            root, generation_hex[0] ? generation_hex : NULL);
    }

    /* The native watcher is verify-only by default.  This guard is
     * unconditional across every RELOAD class, including consensus-risk and
     * owner-unsealed core edits: verification authority never implies runtime
     * publication authority.  Explicit `dev change apply` selects APPLY and
     * proceeds to the transactional activation boundary below. */
    if (plan.action == ZCL_DEVLOOP_RELOAD &&
        !zcl_devloop_publish_mode_applies(publish_mode)) {
        plan.action_name = "verify";
        char execution_why[192] = {0};
        if (failure_execution_id(root, &expected_source,
                                 g_cycle_failure.execution_id,
                                 execution_why, sizeof(execution_why))) {
            g_cycle_failure.execution_ready = true;
            char source_why[256] = {0};
            if (!zcl_dev_source_identity_verify(root, &expected_source,
                                        source_why, sizeof(source_why)))
                return finish_cycle(
                    &plan, files, file_count, "superseded",
                    "source_epoch_cas", started_us,
                    source_why[0] ? source_why
                                  : "source epoch changed before failure lookup",
                    root, NULL);

            struct zcl_dev_failure_record prior;
            char failure_why[192] = {0};
            if (zcl_dev_failure_match_latest(
                    root, expected_source.source_id,
                    expected_source.mutation_id,
                    g_cycle_failure.execution_id, "verify.compile", &prior,
                    failure_why, sizeof(failure_why))) {
                if (!zcl_dev_source_identity_verify(root, &expected_source,
                                            source_why,
                                            sizeof(source_why)))
                    return finish_cycle(
                        &plan, files, file_count, "superseded",
                        "source_epoch_cas", started_us,
                        source_why[0] ? source_why
                                      : "source epoch changed during failure lookup",
                        root, NULL);
                char before_append_execution[65] = {0};
                bool execution_still_exact = failure_execution_id(
                    root, &expected_source, before_append_execution,
                    failure_why, sizeof(failure_why)) &&
                    strcmp(before_append_execution,
                           g_cycle_failure.execution_id) == 0;
                struct zcl_dev_failure_record repeated;
                if (execution_still_exact &&
                    zcl_dev_failure_note_coalesced(
                        root, prior.failure_id, expected_source.source_id,
                        expected_source.mutation_id,
                        g_cycle_failure.execution_id, "verify.compile",
                        &repeated, failure_why, sizeof(failure_why))) {
                    if (!zcl_dev_source_identity_verify(root, &expected_source,
                                                source_why,
                                                sizeof(source_why)))
                        return finish_cycle(
                            &plan, files, file_count, "superseded",
                            "source_epoch_cas", started_us,
                            source_why[0]
                                ? source_why
                                : "source epoch changed after failure lookup",
                            root, NULL);
                    char after_append_execution[65] = {0};
                    bool execution_remains_exact = failure_execution_id(
                        root, &expected_source, after_append_execution,
                        failure_why, sizeof(failure_why)) &&
                        strcmp(after_append_execution,
                               g_cycle_failure.execution_id) == 0;
                    if (execution_remains_exact) {
                        (void)snprintf(g_cycle_failure.failure_id,
                                       sizeof(g_cycle_failure.failure_id), "%s",
                                       repeated.failure_id);
                        (void)snprintf(g_cycle_failure.failure_phase,
                                       sizeof(g_cycle_failure.failure_phase), "%s",
                                       repeated.phase);
                        (void)snprintf(g_cycle_failure.first_error,
                                       sizeof(g_cycle_failure.first_error), "%s",
                                       repeated.first_error);
                        g_cycle_failure.repeat_count = repeated.repeat_count;
                        g_cycle_failure.coalesced = true;
                        fprintf(stderr,
                                "[devloop] unchanged compiler failure coalesced "
                                "failure_id=%s repeat_count=%llu\n",
                                repeated.failure_id,
                                (unsigned long long)repeated.repeat_count);
                        return finish_cycle(
                            &plan, files, file_count, "unchanged_failure",
                            "verify", started_us, "", root, NULL);
                    }
                    fprintf(stderr,
                            "[devloop] compiler execution epoch changed during "
                            "coalescing; running make ff\n");
                }
            }
            if (failure_why[0])
                fprintf(stderr,
                        "[devloop] failure receipt unavailable (safe miss): "
                        "%s\n", failure_why);
        } else {
            /* Negative caching is an optimization, never proof authority. */
            fprintf(stderr,
                    "[devloop] failure execution identity unavailable "
                    "(safe miss): %s\n",
                    execution_why[0] ? execution_why : "unknown");
        }
        char ff_record_arg[160];
        if (!failure_source_record_arg(&expected_source, ff_record_arg,
                                       execution_why,
                                       sizeof(execution_why)))
            return finish_cycle(
                &plan, files, file_count, "rejected", "verify",
                started_us, execution_why[0]
                    ? execution_why : "could not bind source record to make ff",
                root, NULL);
        const char *ff_argv[] = {
            "make", "--no-print-directory", ff_record_arg, "ff", NULL
        };
        if (!zcl_devloop_process_run(root, ff_argv, 900000, &result) ||
            !result_ok(&result)) {
            output_capsule(&result, capsule);
            char post_source_why[256] = {0};
            if (!zcl_dev_source_identity_verify(root, &expected_source,
                                        post_source_why,
                                        sizeof(post_source_why)))
                return finish_cycle(
                    &plan, files, file_count, "superseded",
                    "source_epoch_cas", started_us,
                    post_source_why[0]
                        ? post_source_why
                        : "source epoch changed during failed verification",
                    root, NULL);
            char post_execution[65] = {0};
            char post_execution_why[192] = {0};
            bool execution_stable =
                g_cycle_failure.execution_ready &&
                failure_execution_id(root, &expected_source, post_execution,
                                     post_execution_why,
                                     sizeof(post_execution_why)) &&
                strcmp(post_execution, g_cycle_failure.execution_id) == 0;
            if (execution_stable &&
                zcl_devloop_deterministic_compile_failure(
                    &result, g_cycle_failure.first_error)) {
                g_cycle_failure.cacheable = true;
                (void)snprintf(g_cycle_failure.failure_phase,
                               sizeof(g_cycle_failure.failure_phase),
                               "verify.compile");
            } else if (g_cycle_failure.execution_ready && !execution_stable) {
                fprintf(stderr,
                        "[devloop] failure execution epoch changed or could "
                        "not be revalidated (safe miss): %s\n",
                        post_execution_why[0] ? post_execution_why
                                              : "execution_epoch_changed");
            }
            fprintf(stderr,
                    "[devloop] verify (make ff) failed — fix, then run "
                    "`dev ff` for an explicit unchanged retry\n");
            return finish_cycle(&plan, files, file_count, "rejected",
                                "verify", started_us,
                                capsule[0] ? capsule : "make ff failed",
                                root, NULL);
        }
        char source_why[256] = {0};
        if (!zcl_dev_source_identity_verify(root, &expected_source,
                                    source_why, sizeof(source_why)))
            return finish_cycle(
                &plan, files, file_count, "superseded", "source_epoch_cas",
                started_us,
                source_why[0] ? source_why
                              : "source epoch changed during verification",
                root, NULL);
        fprintf(stderr,
                "[devloop] verified in %llds — runtime publication remains "
                "owner-contained\n",
                (long long)((platform_time_monotonic_us() - started_us) /
                            1000000));
        return finish_cycle(&plan, files, file_count, "passed", "verify",
                            started_us, "", root, NULL);
    }

transactional_reload:
    /* Retained Wave 3.2 machinery. Public apply/auto entrypoints are
     * contained before reaching this label; ZCL_DEV_NATIVE_ACTIVATION is an
     * engine selector, never authority. Hermetic tests cover the engine while
     * the immutable epoch/proof/CAS/rollback transaction is unfinished. */
    if (dev_activation_native_enabled()) {
        const char *build_argv[] = {
            "make", "--no-print-directory", "fast-rebuild", NULL
        };
        if (!zcl_devloop_process_run(root, build_argv, 600000, &result) ||
            !result_ok(&result)) {
            output_capsule(&result, capsule);
            return finish_cycle(&plan, files, file_count, "rejected",
                                "transactional_reload", started_us,
                                capsule[0] ? capsule : "fast-rebuild failed",
                                root, NULL);
        }

        struct dev_activation_cycle_request creq;
        /* The generation's source_id_sha256 is activation authority. The Git
         * commit field is intentionally empty here; it is optional trace
         * metadata and inability to derive it must never select a backend or
         * alter an activation verdict. */
        if (dev_activation_request_from_cycle(root, "", &creq)) {
            char source_why[256] = {0};
            if (!zcl_dev_source_identity_verify(root, &expected_source,
                                        source_why, sizeof(source_why))) {
                return finish_cycle(&plan, files, file_count, "superseded",
                                    "source_epoch_cas", started_us,
                                    source_why[0] ? source_why
                                                  : "source epoch changed before activation",
                                    root, NULL);
            }
            creq.req.source_identity = expected_source.source_id;
            struct dev_activation_ops ops;
            dev_activation_default_ops(&creq.req, &ops);
            struct dev_activation_result ar = {0};
            dev_activation_run(&creq.req, &ops, &ar);

            struct dev_activation_cycle_outcome outcome;
            dev_activation_map_result(&ar, &outcome);
            if (outcome.ok)
                return finish_cycle(&plan, files, file_count, "passed",
                                    "transactional_reload", started_us, "",
                                    root, outcome.generation_hex[0]
                                          ? outcome.generation_hex : NULL);
            return finish_cycle(&plan, files, file_count, "rejected",
                                "transactional_reload", started_us,
                                outcome.capsule[0] ? outcome.capsule
                                    : "native activation failed",
                                root, NULL);
        }
        /* A non-identity precondition the native engine cannot satisfy (for
         * example HOME unset) falls through to the compatibility backend. */
        fprintf(stderr,
                "[devloop] retained native activation preconditions unmet; "
                "shell backend remains publication-contained\n");
    }

    /* Retained compatibility backend for hermetic transaction work. Public
     * publication is contained before this label for every engine-selector
     * value; this fixed argv is not activation authority. */
    char source_arg[96];
    int source_arg_n = snprintf(source_arg, sizeof(source_arg),
                                "ZCL_DEV_SOURCE_ID=%s",
                                expected_source.source_id);
    if (source_arg_n <= 0 || (size_t)source_arg_n >= sizeof(source_arg))
        return finish_cycle(&plan, files, file_count, "rejected",
                            "source_epoch_cas", started_us,
                            "could not bind source identity to activation",
                            root, NULL);
    char source_verify_why[256] = {0};
    if (!zcl_dev_source_identity_verify(root, &expected_source,
                                source_verify_why,
                                sizeof(source_verify_why))) {
        return finish_cycle(&plan, files, file_count, "superseded",
                            "source_epoch_cas", started_us,
                            source_verify_why[0]
                                ? source_verify_why
                                : "source epoch changed before activation",
                            root, NULL);
    }
    const char *reload_argv[] = {
        "make", "--no-print-directory", "agent-deploy-fast", source_arg,
        NULL
    };
    if (!zcl_devloop_process_run(root, reload_argv, 900000, &result) ||
        !result_ok(&result)) {
        output_capsule(&result, capsule);
        return finish_cycle(&plan, files, file_count, "rejected",
                            "transactional_reload", started_us, capsule,
                            root, NULL);
    }
    /* The generation id for a RELOAD cycle: read it back from the
     * zcl.agent_dev_deploy.v1 state file the just-run deploy-dev-lane.sh
     * wrote (see read_reload_generation() above). Best-effort, same
     * fail-open contract as the hotswap path. */
    char generation_hex[65];
    read_reload_generation(generation_hex);
    return finish_cycle(&plan, files, file_count, "passed",
                        "transactional_reload", started_us, "",
                        root, generation_hex[0] ? generation_hex : NULL);
#endif
}

/* A one-shot cycle is itself the explicit publication command.  Persistent
 * watchers call zcl_devloop_run_cycle_mode(...VERIFY_ONLY) instead. */
int zcl_devloop_run_cycle(const char *repo_root,
                          const char *const *files,
                          size_t file_count)
{
    return zcl_devloop_run_cycle_mode(repo_root, files, file_count,
                                      ZCL_DEVLOOP_PUBLISH_APPLY);
}

int zcl_devloop_print_status(void)
{
    char body[16384], why[160] = {0};
    size_t len = 0;
    enum zcl_devloop_state_lookup lookup =
        zcl_devloop_cycle_state_read(".", body, sizeof(body), &len, NULL,
                                     why, sizeof(why));
    if (lookup == ZCL_DEVLOOP_STATE_ABSENT) {
        printf("{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"unavailable\","
               "\"agent_next_action\":\"keep editing or run dev loop watch\"}\n");
        return 0;
    }
    if (lookup != ZCL_DEVLOOP_STATE_FOUND) {
        fprintf(stderr, "[devloop] status: invalid cycle state: %s\n",
                why[0] ? why : "unknown");
        return 1;
    }
    fwrite(body, 1, len, stdout);
    if (len == 0 || body[len - 1] != '\n')
        fputc('\n', stdout);
    return 0;
}
