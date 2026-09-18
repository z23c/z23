/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: smallest C23 client for Muse's session protocol (MSP) over the
 * stdio of an installed `muse serve` host. It owns exactly one child process
 * and speaks only the stable MSP surface observed from `muse schema`:
 * initialize, session/start, session/list, turn/start, turn/cancel,
 * approval/decide, userInput/cancel and usage/read, plus the async
 * notifications the host emits (turn/completed, item deltas, token usage,
 * approval/request, userInput/request).
 *
 * What it does not do, by design:
 * - It never recreates Muse's coding harness and never falls back to a bare
 *   provider API loop: without a `muse serve` child there is no session.
 * - It never overrides the session provider or model: the host default
 *   applies unless the authorizing task names one through the policy.
 * - It never approves allowAll: session approval modes are selected from the
 *   host's closed set and allowAll is refused at the boundary.
 * - Cross-host resume is a documented gap: this build of `muse serve`
 *   defers session/resume (methodNotFound), so a session is reusable while
 *   its host lives and durable on disk afterwards for `muse resume`.
 */
#ifndef ZCL_SERVICES_MUSE_SESSION_H
#define ZCL_SERVICES_MUSE_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define MUSE_SESSION_ID_MAX 128
#define MUSE_TURN_ID_MAX 128
#define MUSE_COMMAND_ID_MAX 64
#define MUSE_ERROR_MAX 256

struct muse_session_limits {
    int64_t open_timeout_ms;   /* handshake bound; <= 0 selects 15000 */
    int64_t turn_timeout_ms;   /* bound per wait call; <= 0 selects 600000 */
    /* Token cap means "may consume at most N": consumption beyond N fails
     * the running wait with kind "tokenBudget"; reaching exactly N
     * completes and the next turn is refused. 0 means no cap. */
    uint64_t max_total_tokens;
    size_t max_text_bytes;     /* captured agent-text bound; 0 selects 65536 */
};

/* Maps MSP approvals onto Z23 permissions. Approvals whose subject carries an
 * allowlisted workspace-relative path prefix or allowlisted exact command are
 * approved once; every other approval is denied. userInput prompts are always
 * declined: a worker has no interactive user. */
struct muse_session_policy {
    const char *approval_mode; /* NULL selects "denyUnmatched" */
    const char *model;         /* NULL keeps the host default model */
    const char *const *allow_paths;
    size_t allow_path_count;
    const char *const *allow_commands;
    size_t allow_command_count;
};

struct muse_session;

struct muse_turn_outcome {
    char terminal[16]; /* "completed", "failed" or "cancelled" */
    char *text;        /* bounded captured agent text, never NULL */
    uint64_t input_tokens;
    uint64_t output_tokens;
    uint64_t total_tokens;
    /* The part of input_tokens the host served from its prompt cache
     * (usage cacheReadTokens, else cachedTokens; 0 when not reported), and
     * total_tokens less that: what the session cap is charged. An agent
     * re-reads its whole context every step, so a real turn's input is
     * ~90% cache reads; charging those at full weight made the cap trip
     * on context, not work. total_tokens stays the raw host figure. */
    uint64_t cached_input_tokens;
    uint64_t billed_tokens;
    int64_t duration_ms; /* -1 when the host did not measure one */
    unsigned approvals_approved;
    unsigned approvals_denied;
    unsigned inputs_declined;
};

/* Launches `muse serve` (argv0 names the installed `muse` binary) and runs
 * the initialize handshake. Returns NULL with err set on failure. */
struct muse_session *muse_session_open(const char *serve_argv0,
    const struct muse_session_limits *limits, char err[MUSE_ERROR_MAX]);
void muse_session_close(struct muse_session *s);
const char *muse_session_last_error(const struct muse_session *s);
const char *muse_session_last_kind(const struct muse_session *s);
bool muse_session_last_retryable(const struct muse_session *s);

/* Mint one UUIDv7 idempotency handle. Callers persist the handle beside the
 * Z23 action/lease so a retry replays the identical command. */
bool muse_session_command_id(char out[MUSE_COMMAND_ID_MAX]);

/* Starts one session bound to workspace_root with the policy approval mode.
 * The effective provider/model are reported back; they are never overridden
 * here. Fails when the mode is "allowAll". */
int muse_session_start(struct muse_session *s, const char *command_id,
    const char *workspace_root, const struct muse_session_policy *policy,
    char session_id[MUSE_SESSION_ID_MAX],
    char provider_out[64], char model_out[128]);

int muse_session_turn(struct muse_session *s, const char *command_id,
    const char *session_id, const char *prompt,
    char turn_id[MUSE_TURN_ID_MAX]);

/* Drains host traffic until this turn's turn/completed (or turn/unqueued)
 * lands, the token cap trips, or the turn timeout elapses. Server-initiated
 * approval/userInput requests are answered from the policy while waiting. */
int muse_session_wait(struct muse_session *s, const char *session_id,
    const char *turn_id, const struct muse_session_policy *policy,
    struct muse_turn_outcome *out);

/* Admits cancellation; the turn is over when a later wait folds the terminal
 * "cancelled" record. turn_id may be "" to target the foreground turn. */
int muse_session_cancel(struct muse_session *s, const char *command_id,
    const char *session_id, const char *turn_id);

void muse_turn_outcome_free(struct muse_turn_outcome *out);

/* Read-only observation of the owned host child, for diagnostics and crash
 * drills (target exactly this host, never a shared process by name). Killing
 * the host invalidates in-flight turns; -1 when no child is owned. */
pid_t muse_session_host_pid(const struct muse_session *s);

#ifdef ZCL_TESTING
/* Test seam: attach to an already-spawned transport (the caller owns the
 * fork) and run the initialize handshake over it. Mirrors the
 * "force the outcome, run the real decision code" shape of
 * build_fabric_worker_capabilities_for_test(). */
struct muse_session *muse_session_attach(pid_t child, int to_fd, int from_fd,
    const struct muse_session_limits *limits);
#endif

#endif /* ZCL_SERVICES_MUSE_SESSION_H */
