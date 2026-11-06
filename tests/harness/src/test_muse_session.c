/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: prove the MSP adapter runs the full worker journey against a
 * scripted in-process host: handshake, start, turn, approval allow/deny
 * mapping, user-input decline, token accounting, idempotent retry, cancel,
 * budgets and the allowAll refusal. No `muse` binary and no network. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"
#include "services/muse_session.h"
#include "json/json.h"
#if !defined(_WIN32)
#include <sys/types.h>
#include <sys/wait.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MS_CHECK(label, expression) do { \
    bool ok = (expression); \
    printf("muse_session: %s... %s\n", label, ok ? "OK" : "FAIL"); \
    if (!ok) ++failures; \
} while (0)

#if defined(_WIN32)
int test_muse_session(void)
{
    printf("muse_session: windows has no fork transport... SKIP\n");
    return 0;
}
#else

#include "test/muse_fake_host.h"
#include "../../../contexts/commons/services/src/muse_session_internal.h"

#include <limits.h>

static int ms_failures_journey(void)
{
    int failures = 0;
    int ev[2];
    if (pipe(ev) != 0) return 1;
    s_evidence_fd = ev[1];
    struct muse_session_limits limits = {
        .open_timeout_ms = 10000, .turn_timeout_ms = 15000,
    };
    struct fake_host host = {0};
    MS_CHECK("journey attach", spawn_fake(FAKE_JOURNEY, ev[0], &limits,
        &host));
    if (!host.session) {
        close(ev[0]); close(ev[1]);
        return failures;
    }
    const char *paths[] = { "notes/" };
    const struct muse_session_policy policy = {
        .approval_mode = "denyUnmatched", .allow_paths = paths,
        .allow_path_count = 1, .model = "m-test",
    };
    char sid[MUSE_SESSION_ID_MAX] = {0};
    char prov[64] = {0}, model[128] = {0};
    char sc[MUSE_COMMAND_ID_MAX];
    MS_CHECK("command id mints", muse_session_command_id(sc));
    MS_CHECK("start", muse_session_start(host.session, sc,
        "/z23-muse-test/ws", &policy, sid, prov, model) == 0);
    MS_CHECK("session id", strcmp(sid, "sess-test-1") == 0);
    MS_CHECK("provider reported, never overridden",
        strcmp(prov, "meta") == 0 && strcmp(model, "m-test") == 0);
    char tc[MUSE_COMMAND_ID_MAX];
    (void)muse_session_command_id(tc);
    char tid[MUSE_TURN_ID_MAX] = {0};
    MS_CHECK("turn", muse_session_turn(host.session, tc, sid,
        "do the thing", tid) == 0);
    MS_CHECK("turn id echoes command", strcmp(tid, tc) == 0);
    struct muse_turn_outcome out = {0};
    MS_CHECK("wait completes", muse_session_wait(host.session, sid, tid,
        &policy, &out) == 0);
    MS_CHECK("terminal completed", strcmp(out.terminal, "completed") == 0);
    MS_CHECK("agent text", out.text && strcmp(out.text, "fake-ok") == 0);
    MS_CHECK("token accounting",
        out.input_tokens == 10 && out.output_tokens == 5 &&
        out.total_tokens == 15);
    MS_CHECK("duration", out.duration_ms == 7);
    MS_CHECK("approval allow+deny",
        out.approvals_approved == 1 && out.approvals_denied == 1);
    MS_CHECK("input declined", out.inputs_declined == 1);
    muse_turn_outcome_free(&out);
    MS_CHECK("cancel admitted", muse_session_cancel(host.session, tc, sid,
        tid) == 0);
    close_fake(&host);
    close(ev[1]);
    s_evidence_fd = -1;
    char *evidence = read_evidence(ev[0]);
    close(ev[0]);
    MS_CHECK("evidence present", evidence && evidence[0] != '\0');
    MS_CHECK("evidence: path approval allowed",
        evidence_has(evidence, "decide:c-allow:7"));
    MS_CHECK("evidence: shell approval denied",
        evidence_has(evidence, "decide:c-deny:\"req-s2\""));
    MS_CHECK("evidence: input declined", evidence_has(evidence,
        "declined:ui-1"));
    MS_CHECK("evidence: exactly two decisions",
        evidence_count(evidence, "decide:") == 2);
    MS_CHECK("evidence: turn command seen", evidence_has(evidence,
        "turn-cmd:"));
    MS_CHECK("evidence: model selection seen", evidence_has(evidence,
        "model:m-test"));
    MS_CHECK("evidence: cancel seen", evidence_has(evidence, "cancel:"));
    free(evidence);
    return failures;
}

static int ms_failures_model_selection(bool reject)
{
    int failures = 0;
    int ev[2];
    if (pipe(ev) != 0) return 1;
    s_evidence_fd = ev[1];
    struct muse_session_limits limits = {.open_timeout_ms = 10000};
    struct fake_host host = {0};
    if (!spawn_fake(FAKE_JOURNEY, ev[0], &limits, &host)) {
        close(ev[0]); close(ev[1]); s_evidence_fd = -1;
        return 1;
    }
    struct muse_session_policy policy = {
        .model = reject ? "m-rejected" : "m-selected",
    };
    char command[MUSE_COMMAND_ID_MAX], sid[MUSE_SESSION_ID_MAX];
    char provider[64], model[128];
    bool id_ok = muse_session_command_id(command);
    int rc = id_ok ? muse_session_start(host.session, command,
        "/z23-muse-test/ws", &policy, sid, provider, model) : -1;
    MS_CHECK("explicit model uses installed selection schema",
        id_ok && (reject ? rc != 0 : rc == 0));
    close_fake(&host);
    close(ev[1]); s_evidence_fd = -1;
    char *evidence = read_evidence(ev[0]);
    close(ev[0]);
    MS_CHECK("model selection sent exactly once with requested identity",
        evidence_count(evidence, "model:") == 1 &&
        evidence_has(evidence, reject ? "model:m-rejected" : "model:m-selected"));
    MS_CHECK("selection never substitutes a provider or profile",
        !evidence_has(evidence, "model-route-override"));
    MS_CHECK("selection test starts no turn or fallback",
        !evidence_has(evidence, "turn-cmd:"));
    free(evidence);
    return failures;
}

static int ms_failures_retry(void)
{
    int failures = 0;
    int ev[2];
    if (pipe(ev) != 0) return 1;
    s_evidence_fd = ev[1];
    struct muse_session_limits limits = {
        .open_timeout_ms = 10000, .turn_timeout_ms = 15000,
    };
    struct fake_host host = {0};
    MS_CHECK("retry attach", spawn_fake(FAKE_RETRY, ev[0], &limits,
        &host));
    if (!host.session) {
        close(ev[0]); close(ev[1]);
        return failures;
    }
    struct muse_session_policy policy = {0};
    char sid[MUSE_SESSION_ID_MAX] = {0};
    char sc[MUSE_COMMAND_ID_MAX], prov[64], model[128];
    (void)muse_session_command_id(sc);
    MS_CHECK("retry start", muse_session_start(host.session, sc,
        "/z23-muse-test/ws", &policy, sid, prov, model) == 0);
    char tc[MUSE_COMMAND_ID_MAX];
    (void)muse_session_command_id(tc);
    char first[MUSE_TURN_ID_MAX] = {0}, second[MUSE_TURN_ID_MAX] = {0};
    MS_CHECK("first turn", muse_session_turn(host.session, tc, sid,
        "again", first) == 0);
    /* Idempotent retry replays the identical command id. */
    MS_CHECK("retry turn", muse_session_turn(host.session, tc, sid,
        "again", second) == 0);
    MS_CHECK("retry deduplicates", strcmp(first, second) == 0 &&
        strcmp(first, "turn-fixed") == 0);
    struct muse_turn_outcome out = {0};
    MS_CHECK("retry wait", muse_session_wait(host.session, sid, first,
        &policy, &out) == 0);
    MS_CHECK("retry terminal", strcmp(out.terminal, "completed") == 0);
    muse_turn_outcome_free(&out);
    close_fake(&host);
    close(ev[1]);
    s_evidence_fd = -1;
    char *evidence = read_evidence(ev[0]);
    close(ev[0]);
    /* One command id observed twice proves the replay was byte-identical. */
    int hits = 0;
    if (evidence) {
        char needle[256];
        (void)snprintf(needle, sizeof(needle), "turn-cmd:%s", tc);
        const char *at = evidence;
        while ((at = strstr(at, needle)) != NULL) {
            hits++;
            at += strlen(needle);
        }
    }
    MS_CHECK("replay carried the same command", hits == 2);
    free(evidence);
    return failures;
}

static int ms_failures_refusals(void)
{
    int failures = 0;
    int ev[2];
    if (pipe(ev) != 0) return 1;
    s_evidence_fd = ev[1];
    struct muse_session_limits limits = {
        .open_timeout_ms = 10000, .turn_timeout_ms = 15000,
    };
    struct fake_host host = {0};
    MS_CHECK("refusal attach", spawn_fake(FAKE_HANDSHAKE, ev[0], &limits,
        &host));
    if (!host.session) {
        close(ev[0]); close(ev[1]);
        return failures;
    }
    struct muse_session_policy greedy = { .approval_mode = "allowAll" };
    char sid[MUSE_SESSION_ID_MAX] = {0};
    char sc[MUSE_COMMAND_ID_MAX];
    (void)muse_session_command_id(sc);
    MS_CHECK("allowAll refused",
        muse_session_start(host.session, sc, "/z23-muse-test/ws", &greedy,
            sid, NULL, NULL) != 0);
    MS_CHECK("refusal kind",
        strcmp(muse_session_last_kind(host.session), "policy") == 0);
    struct muse_session_limits capped = {
        .open_timeout_ms = 10000, .turn_timeout_ms = 15000,
        .max_total_tokens = 15,
    };
    close_fake(&host);
    MS_CHECK("capped attach", spawn_fake(FAKE_JOURNEY, ev[0], &capped,
        &host));
    if (!host.session) {
        close(ev[0]); close(ev[1]);
        return failures;
    }
    struct muse_session_policy policy = {0};
    (void)muse_session_command_id(sc);
    MS_CHECK("capped start", muse_session_start(host.session, sc,
        "/z23-muse-test/ws", &policy, sid, NULL, NULL) == 0);
    char tc[MUSE_COMMAND_ID_MAX];
    (void)muse_session_command_id(tc);
    char tid[MUSE_TURN_ID_MAX] = {0};
    MS_CHECK("first capped turn", muse_session_turn(host.session, tc, sid,
        "spend", tid) == 0);
    struct muse_turn_outcome out = {0};
    MS_CHECK("capped wait", muse_session_wait(host.session, sid, tid,
        &policy, &out) == 0);
    muse_turn_outcome_free(&out);
    char tc2[MUSE_COMMAND_ID_MAX];
    (void)muse_session_command_id(tc2);
    char tid2[MUSE_TURN_ID_MAX] = {0};
    MS_CHECK("spent budget refuses",
        muse_session_turn(host.session, tc2, sid, "more", tid2) != 0);
    MS_CHECK("budget kind",
        strcmp(muse_session_last_kind(host.session), "tokenBudget") == 0);
    close_fake(&host);
    close(ev[1]);
    s_evidence_fd = -1;
    char *evidence = read_evidence(ev[0]);
    close(ev[0]);
    MS_CHECK("refused turn never sent", !evidence_has(evidence, tc2));
    free(evidence);
    return failures;
}

static int ms_failures_not_loaded(void)
{
    int failures = 0;
    int ev[2];
    if (pipe(ev) != 0) return 1;
    s_evidence_fd = ev[1];
    struct muse_session_limits limits = {
        .open_timeout_ms = 10000, .turn_timeout_ms = 15000,
    };
    struct fake_host host = {0};
    MS_CHECK("notLoaded attach", spawn_fake(FAKE_NOT_LOADED, ev[0],
        &limits, &host));
    if (!host.session) {
        close(ev[0]); close(ev[1]);
        return failures;
    }
    struct muse_session_policy policy = {0};
    char sid[MUSE_SESSION_ID_MAX] = {0};
    char sc[MUSE_COMMAND_ID_MAX];
    (void)muse_session_command_id(sc);
    MS_CHECK("notLoaded start", muse_session_start(host.session, sc,
        "/z23-muse-test/ws", &policy, sid, NULL, NULL) == 0);
    char tc[MUSE_COMMAND_ID_MAX];
    (void)muse_session_command_id(tc);
    char tid[MUSE_TURN_ID_MAX] = {0};
    MS_CHECK("stale turn fails", muse_session_turn(host.session, tc,
        "sess-gone", "hello", tid) != 0);
    MS_CHECK("stale kind",
        strcmp(muse_session_last_kind(host.session), "sessionNotLoaded") ==
        0);
    MS_CHECK("stale is not retryable",
        !muse_session_last_retryable(host.session));
    close_fake(&host);
    close(ev[0]); close(ev[1]);
    s_evidence_fd = -1;
    return failures;
}

static int ms_failures_prefix(void)
{
    int failures = 0;
    int ev[2];
    if (pipe(ev) != 0) return 1;
    s_evidence_fd = ev[1];
    struct muse_session_limits limits = {
        .open_timeout_ms = 10000, .turn_timeout_ms = 15000,
    };
    struct fake_host host = {0};
    MS_CHECK("prefix attach", spawn_fake(FAKE_PREFIX, ev[0], &limits,
        &host));
    if (!host.session) {
        close(ev[0]); close(ev[1]);
        return failures;
    }
    MS_CHECK("host pid observable",
        muse_session_host_pid(host.session) == host.child &&
        host.child > 0);
    const char *paths[] = { "notes/", "src/sum.c" };
    const char *cmds[] = { "cc -o sum_test" };
    struct muse_session_policy policy = {
        .approval_mode = "denyUnmatched",
        .allow_paths = paths, .allow_path_count = 2,
        .allow_commands = cmds, .allow_command_count = 1,
    };
    char sid[MUSE_SESSION_ID_MAX] = {0};
    char sc[MUSE_COMMAND_ID_MAX];
    (void)muse_session_command_id(sc);
    MS_CHECK("prefix start", muse_session_start(host.session, sc,
        "/z23-muse-test/ws", &policy, sid, NULL, NULL) == 0);
    char tc[MUSE_COMMAND_ID_MAX];
    (void)muse_session_command_id(tc);
    char tid[MUSE_TURN_ID_MAX] = {0};
    MS_CHECK("prefix turn", muse_session_turn(host.session, tc, sid,
        "probe", tid) == 0);
    struct muse_turn_outcome out = {0};
    MS_CHECK("prefix wait", muse_session_wait(host.session, sid, tid,
        &policy, &out) == 0);
    MS_CHECK("prefix terminal", strcmp(out.terminal, "completed") == 0);
    MS_CHECK("prefix text", out.text && strcmp(out.text, "prefix-ok") == 0);
    MS_CHECK("terminal usage replaces events",
        out.input_tokens == 100 && out.output_tokens == 50 &&
        out.total_tokens == 160);
    MS_CHECK("prefix allow/deny",
        out.approvals_approved == 4 && out.approvals_denied == 4);
    muse_turn_outcome_free(&out);
    close_fake(&host);
    close(ev[1]);
    s_evidence_fd = -1;
    char *evidence = read_evidence(ev[0]);
    close(ev[0]);
    MS_CHECK("prefix evidence present", evidence && evidence[0] != '\0');
    MS_CHECK("prefix: eight decisions",
        evidence_count(evidence, "decide:") == 8);
    MS_CHECK("prefix: four allows",
        evidence_count(evidence, "decide:c-allow") == 4);
    MS_CHECK("prefix: four denies",
        evidence_count(evidence, "decide:c-deny") == 4);
    free(evidence);
    return failures;
}

/* Cap contract "may consume at most N": totals N-1 and N complete and only
 * N+1 trips mid-turn; a spent budget refuses the next turn unsent. */
static int ms_failures_boundary_once(long in, long out, long total,
    uint64_t cap, bool expect_trip, bool expect_refuse_next)
{
    int failures = 0;
    s_use_in = in;
    s_use_out = out;
    s_use_total = total;
    int ev[2];
    if (pipe(ev) != 0) return 1;
    s_evidence_fd = ev[1];
    struct muse_session_limits limits = {
        .open_timeout_ms = 10000, .turn_timeout_ms = 15000,
        .max_total_tokens = cap,
    };
    struct fake_host host = {0};
    char tag[128];
    (void)snprintf(tag, sizeof(tag), "cap=%llu total=%ld",
        (unsigned long long)cap, total);
    if (!spawn_fake(FAKE_JOURNEY, ev[0], &limits, &host)) {
        printf("muse_session: boundary %s attach... FAIL\n", tag);
        close(ev[0]); close(ev[1]);
        return 1;
    }
    struct muse_session_policy policy = {0};
    char sid[MUSE_SESSION_ID_MAX] = {0};
    char sc[MUSE_COMMAND_ID_MAX];
    (void)muse_session_command_id(sc);
    bool ok_start = muse_session_start(host.session, sc,
        "/z23-muse-test/ws", &policy, sid, NULL, NULL) == 0;
    char tc[MUSE_COMMAND_ID_MAX];
    (void)muse_session_command_id(tc);
    char tid[MUSE_TURN_ID_MAX] = {0};
    bool ok_turn = ok_start && muse_session_turn(host.session, tc, sid,
        "spend", tid) == 0;
    struct muse_turn_outcome outcome = {0};
    bool ok_wait = ok_turn && muse_session_wait(host.session, sid, tid,
        &policy, &outcome) == 0;
    if (expect_trip) {
        MS_CHECK("over-cap wait trips", !ok_wait);
        MS_CHECK("trip kind",
            strcmp(muse_session_last_kind(host.session), "tokenBudget") ==
            0);
    } else {
        MS_CHECK("at-cap wait completes", ok_wait);
        MS_CHECK("at-cap total",
            (long long)outcome.total_tokens == (long long)total);
        MS_CHECK("cached usage retained once",
            outcome.cached_input_tokens == (uint64_t)s_use_cached);
    }
    muse_turn_outcome_free(&outcome);
    char tc2[MUSE_COMMAND_ID_MAX] = {0};
    /* A tripped first wait ends the case: there is no next turn. */
    bool refused = expect_trip || !ok_wait;
    if (!expect_trip) {
        (void)muse_session_command_id(tc2);
        char tid2[MUSE_TURN_ID_MAX] = {0};
        refused = muse_session_turn(host.session, tc2, sid, "more",
            tid2) != 0;
        if (expect_refuse_next) {
            MS_CHECK("spent budget refuses next", refused);
            MS_CHECK("refusal kind",
                strcmp(muse_session_last_kind(host.session),
                    "tokenBudget") == 0);
        } else {
            /* Admitted (14 < 15) but the running total 14+14 exceeds the
             * cap, so the second wait must trip mid-turn. */
            MS_CHECK("remaining budget admits next", !refused);
            struct muse_turn_outcome o2 = {0};
            MS_CHECK("second wait trips on running total",
                muse_session_wait(host.session, sid, tid2, &policy,
                    &o2) != 0);
            MS_CHECK("second trip kind",
                strcmp(muse_session_last_kind(host.session),
                    "tokenBudget") == 0);
            MS_CHECK("second outcome is turn-local",
                o2.total_tokens == (uint64_t)total &&
                o2.cached_input_tokens == (uint64_t)s_use_cached);
            muse_turn_outcome_free(&o2);
        }
    }
    close_fake(&host);
    close(ev[1]);
    s_evidence_fd = -1;
    char *evidence = read_evidence(ev[0]);
    close(ev[0]);
    MS_CHECK("boundary evidence present", evidence && evidence[0] != '\0');
    if (expect_refuse_next && !expect_trip)
        MS_CHECK("refused turn never sent", !evidence_has(evidence, tc2));
    if (expect_trip)
        MS_CHECK("tripped turn was admitted", evidence_has(evidence, tc));
    free(evidence);
    s_use_in = 10;
    s_use_out = 5;
    s_use_total = 15;
    return failures;
}

static int ms_failures_boundary(void)
{
    int failures = 0;
    failures += ms_failures_boundary_once(9, 5, 14, 15, false, false);
    failures += ms_failures_boundary_once(10, 5, 15, 15, false, true);
    failures += ms_failures_boundary_once(10, 6, 16, 15, true, true);
    /* The local token cap excludes cache reads: 45 total less 35 cached
     * consumes 10. The first turn fits 15; the second exceeds it. */
    s_use_cached = 35;
    failures += ms_failures_boundary_once(40, 5, 45, 15, false, false);
    s_use_cumulative = true;
    failures += ms_failures_boundary_once(40, 5, 45, 15, false, false);
    s_use_cumulative = false;
    s_use_cached = 0;
    return failures;
}

static int ms_failures_usage_settlement(enum fake_mode mode)
{
    int failures = 0, ev[2];
    if (pipe(ev) != 0) return 1;
    s_evidence_fd = ev[1];
    struct muse_session_limits limits = {
        .open_timeout_ms = 10000, .turn_timeout_ms = 15000,
        .max_total_tokens = mode == FAKE_USAGE_TERMINAL ? 15 : 30,
    };
    struct fake_host host = {0};
    MS_CHECK("usage settlement attach", spawn_fake(mode, ev[0], &limits,
        &host));
    if (!host.session) {
        close(ev[0]); close(ev[1]);
        s_evidence_fd = -1;
        return failures;
    }
    struct muse_session_policy policy = {0};
    char sid[MUSE_SESSION_ID_MAX] = {0}, tid[MUSE_TURN_ID_MAX] = {0};
    char command[MUSE_COMMAND_ID_MAX] = {0};
    (void)muse_session_command_id(command);
    MS_CHECK("usage settlement start", muse_session_start(host.session,
        command, "/z23-muse-test/ws", &policy, sid, NULL, NULL) == 0);
    (void)muse_session_command_id(command);
    MS_CHECK("usage settlement turn", muse_session_turn(host.session,
        command, sid, "usage", tid) == 0);
    struct muse_turn_outcome out = {0};
    int rc = muse_session_wait(host.session, sid, tid, &policy, &out);
    if (mode == FAKE_USAGE_MATCH) {
        MS_CHECK("normalized terminal reconciles", rc == 0);
        MS_CHECK("unique cache-exclusive events retain normalized totals",
            out.input_tokens == 80 && out.output_tokens == 10 &&
            out.cached_input_tokens == 70 && out.total_tokens == 90 &&
            out.billed_tokens == 20);
    } else {
        const char *kind = mode == FAKE_USAGE_MISMATCH ?
            "usageMismatch" : "tokenBudget";
        MS_CHECK("usage settlement refuses", rc != 0 &&
            strcmp(muse_session_last_kind(host.session), kind) == 0);
        (void)muse_session_command_id(command);
        MS_CHECK("unsettled or spent usage refuses another turn",
            muse_session_turn(host.session, command, sid, "more", tid) != 0);
    }
    muse_turn_outcome_free(&out);
    close_fake(&host);
    close(ev[1]);
    s_evidence_fd = -1;
    char *evidence = read_evidence(ev[0]);
    close(ev[0]);
    MS_CHECK("usage settlement sends exactly one turn",
        evidence && evidence_count(evidence, "turn-cmd:") == 1);
    if (mode != FAKE_USAGE_MATCH)
        MS_CHECK("refused usage turn remains unsent",
            evidence && !evidence_has(evidence, command));
    free(evidence);
    return failures;
}

/* ── mutation-gap tests: the framing, id and transport-failure primitives
 * driven directly over pipes and tiny forked children ───────────────────── */

static void mx_session(struct muse_session *s)
{
    memset(s, 0, sizeof(*s));
    s->child = -1;
    s->to_child = -1;
    s->from_child = -1;
    s->mem_max_events = -1;
}

static bool mx_fed_line(const char *bytes, size_t cap, int expect,
                        const char *want, const char *kind, bool retryable)
{
    int p[2];
    if (pipe(p) != 0)
        return false;
    if (bytes && bytes[0])
        (void)!write(p[1], bytes, strlen(bytes));
    if (!bytes)
        close(p[1]);
    struct muse_session s;
    mx_session(&s);
    s.from_child = p[0];
    char buf[64] = "unset";
    int r = ms_read_line(&s, buf, cap, ms_monotonic_ms() + 5000);
    bool ok = r == expect;
    if (ok && expect == 1)
        ok = strcmp(buf, want) == 0;
    if (ok && expect == -1)
        ok = strcmp(s.kind, kind) == 0 && s.retryable == retryable;
    if (!ok)
        printf("[line r=%d kind=%s] ", r, s.kind);
    if (bytes)
        close(p[1]);
    close(p[0]);
    return ok;
}

static int ms_failures_read_line(void)
{
    int failures = 0;
    MS_CHECK("read_line returns one frame and leaves the rest",
        mx_fed_line("ab\n", 64, 1, "ab", "", false) &&
        mx_fed_line("\n", 64, 1, "", "", false));
    /* cap 8: seven bytes plus the NUL fit, an eighth byte does not. */
    MS_CHECK("read_line frame exactly fits cap-1",
        mx_fed_line("abcdefg\n", 8, 1, "abcdefg", "", false));
    MS_CHECK("read_line frame one byte over cap is frameTooLarge",
        mx_fed_line("abcdefgh\n", 8, -1, "", "frameTooLarge", false));
    MS_CHECK("read_line EOF is a retryable transport failure",
        mx_fed_line(NULL, 64, -1, "", "transport", true));

    int p[2];
    struct muse_session s;
    char buf[64];
    if (pipe(p) != 0)
        return failures + 1;
    mx_session(&s);
    s.from_child = p[0];
    (void)!write(p[1], "x\ny\n", 4);
    MS_CHECK("read_line two frames in one write come out one by one",
        ms_read_line(&s, buf, sizeof(buf), ms_monotonic_ms() + 5000) == 1 &&
        strcmp(buf, "x") == 0 &&
        ms_read_line(&s, buf, sizeof(buf), ms_monotonic_ms() + 5000) == 1 &&
        strcmp(buf, "y") == 0);
    /* Empty pipe, short deadline: a timeout, not an error. */
    MS_CHECK("read_line empty pipe times out with 0 and no failure",
        ms_read_line(&s, buf, sizeof(buf), ms_monotonic_ms() + 30) == 0 &&
        s.kind[0] == '\0');
    (void)!write(p[1], "late\n", 5);
    MS_CHECK("read_line an expired deadline returns 0 before reading",
        ms_read_line(&s, buf, sizeof(buf), ms_monotonic_ms() - 1) == 0 &&
        ms_read_line(&s, buf, sizeof(buf), ms_monotonic_ms() + 5000) == 1 &&
        strcmp(buf, "late") == 0);
    close(p[0]);
    close(p[1]);
    return failures;
}

struct mx_idrow {
    const char *line;
    size_t cap;
    bool ok;
    const char *want;
};

static int ms_failures_raw_id(void)
{
    int failures = 0;
    static const struct mx_idrow rows[] = {
        { "{\"id\":7}", 64, true, "7" },
        { "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"x\"}", 64, true, "9" },
        { "{\"id\": \t12,\"x\":1}", 64, true, "12" },
        { "{\"id\":-3}", 64, true, "-3" },
        { "{\"id\":\"abc\"}", 64, true, "\"abc\"" },
        { "{\"id\":\"\"}", 64, true, "\"\"" },
        { "{\"id\":\"a\\\"b\"}", 64, true, "\"a\\\"b\"" },
        { "{\"id\":\"x\\\\\"}", 64, true, "\"x\\\\\"" },
        { "{\"x\":1}", 64, false, "" },
        { "{\"id\":null}", 64, false, "" },
        { "{\"id\":true}", 64, false, "" },
        { "{\"id\":\"abc}", 64, false, "" },
        { "{\"id\":\"x\\\"", 64, false, "" },
        { "{\"id\":\"abc\"}", 6, true, "\"abc\"" },
        { "{\"id\":\"abc\"}", 5, false, "" },
        { "{\"id\":\"ab\"}", 5, true, "\"ab\"" },
        { "{\"id\":\"ab\"}", 4, false, "" },
        { "{\"id\":\"a\"}", 1, false, "" },
        { "{\"id\":12}", 3, true, "12" },
        { "{\"id\":1}", 1, false, "" },
        { "{\"id\":7}", 0, false, "" },
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        char out[64] = "poison";
        bool got = ms_raw_id(rows[i].line, out, rows[i].cap);
        bool row_ok = got == rows[i].ok &&
                      (!got || strcmp(out, rows[i].want) == 0);
        if (!row_ok)
            printf("[raw_id row %zu got=%d out=%s] ", i, got, out);
        MS_CHECK("raw_id row", row_ok);
    }
    return failures;
}

static bool mx_drain(int fd, char *out, size_t want)
{
    size_t got = 0;
    while (got < want) {
        ssize_t k = read(fd, out + got, want - got);
        if (k <= 0)
            return false;
        got += (size_t)k;
    }
    out[got] = '\0';
    return true;
}

static bool mx_send_roundtrip(const char *method, int id, const char *params)
{
    int p[2];
    if (pipe(p) != 0)
        return false;
    struct muse_session s;
    mx_session(&s);
    s.to_child = p[1];
    char want[600];
    snprintf(want, sizeof(want),
             "{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"%s\",\"params\":%s}\n",
             id, method, params);
    char got[600];
    bool ok = ms_send(&s, id, method, params) &&
              mx_drain(p[0], got, strlen(want)) && strcmp(got, want) == 0;
    close(p[0]);
    close(p[1]);
    return ok;
}

static bool mx_send_overflow(const char *method)
{
    int p[2];
    if (pipe(p) != 0)
        return false;
    struct muse_session s;
    mx_session(&s);
    s.to_child = p[1];
    bool sent = ms_send(&s, 1, method, "{}");
    bool ok = !sent && strcmp(s.kind, "internal") == 0 && !s.retryable &&
              strcmp(s.err, "request head overflow") == 0;
    close(p[1]);
    char b;
    ok = ok && read(p[0], &b, 1) == 0;  /* nothing was written */
    close(p[0]);
    return ok;
}

static int ms_failures_send(void)
{
    int failures = 0;
    char m210[211], m211[212];
    memset(m210, 'm', 210);
    m210[210] = '\0';
    memset(m211, 'm', 211);
    m211[211] = '\0';
    MS_CHECK("send writes the exact JSON-RPC frame",
        mx_send_roundtrip("turn/start", 5, "{\"a\":1}") &&
        mx_send_roundtrip("m", 123, "[]"));
    /* head is 45 bytes plus the method for id 1: 255 fits, 256 does not. */
    MS_CHECK("send head of 255 bytes is accepted",
        mx_send_roundtrip(m210, 1, "{}"));
    MS_CHECK("send head of 256 bytes is refused as internal, nothing written",
        mx_send_overflow(m211));

    int p[2];
    char buf[64];
    if (pipe(p) != 0)
        return failures + 1;
    struct muse_session s;
    mx_session(&s);
    s.to_child = p[1];
    MS_CHECK("send_raw appends exactly one newline",
        ms_send_raw(&s, "{\"k\":1}") && mx_drain(p[0], buf, 8) &&
        strcmp(buf, "{\"k\":1}\n") == 0);
    close(p[0]);
    void (*old)(int) = signal(SIGPIPE, SIG_IGN);
    MS_CHECK("send into a closed pipe is a retryable transport failure",
        !ms_send(&s, 1, "m", "{}") && strcmp(s.kind, "transport") == 0 &&
        s.retryable &&
        strncmp(s.err, "serve stdin write: ", 19) == 0);
    mx_session(&s);
    s.to_child = p[1];
    MS_CHECK("send_raw into a closed pipe fails too",
        !ms_send_raw(&s, "x") && strcmp(s.kind, "transport") == 0);
    (void)signal(SIGPIPE, old);
    close(p[1]);
    return failures;
}

/* Forks a child that closes its stdout end and then either exits with 3,
 * dies on SIGKILL, or idles; checks the recorded stdout-closed reason. */
enum mx_exit_mode { MX_EXIT3, MX_KILL, MX_IDLE };

static bool mx_stdout_closed_case(enum mx_exit_mode mode, long long mem_max,
                                  const char *want_err, bool want_reaped)
{
    int p[2];
    if (pipe(p) != 0)
        return false;
    pid_t pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0) {
        close(p[0]);
        close(p[1]);
        if (mode == MX_EXIT3)
            _exit(3);
        if (mode == MX_KILL)
            (void)kill(getpid(), SIGKILL);
        for (;;)
            pause();
    }
    close(p[1]);
    struct muse_session s;
    mx_session(&s);
    s.child = pid;
    s.from_child = p[0];
    s.mem_max_events = mem_max;
    char buf[64];
    int r = ms_read_line(&s, buf, sizeof(buf), ms_monotonic_ms() + 20000);
    bool ok = r == -1 && strcmp(s.kind, "transport") == 0 && s.retryable &&
              strcmp(s.err, want_err) == 0 &&
              (want_reaped ? s.child == -1 : s.child == pid);
    if (!ok)
        printf("[closed r=%d kind=%s err=%s] ", r, s.kind, s.err);
    if (!want_reaped) {
        (void)kill(pid, SIGKILL);
        (void)waitpid(pid, NULL, 0);
    }
    close(p[0]);
    return ok;
}

static int ms_failures_stdout_closed(void)
{
    int failures = 0;
    MS_CHECK("stdout EOF names the child's exit status and forgets the pid",
        mx_stdout_closed_case(MX_EXIT3, -1, "serve stdout closed, child exit 3",
                              true));
    MS_CHECK("stdout EOF names the child's fatal signal",
        mx_stdout_closed_case(MX_KILL, -1,
                              "serve stdout closed, child signal 9", true));
    /* A counter that cannot have moved past LLONG_MAX never reads as a
     * memory.max charge, so a SIGKILL stays a plain transport close. */
    MS_CHECK("stdout EOF with an unreachable charge baseline stays transport",
        mx_stdout_closed_case(MX_KILL, LLONG_MAX,
                              "serve stdout closed, child signal 9", true));
    /* The idle child is not reaped within the bound: bare close, pid kept. */
    MS_CHECK("stdout EOF with a still-running child is a bare close",
        mx_stdout_closed_case(MX_IDLE, -1, "serve stdout closed", false));
    return failures;
}

static bool mx_uuid_shaped(const char *a)
{
    if (strlen(a) != 36)
        return false;
    for (size_t i = 0; i < 36; i++) {
        bool dash = i == 8 || i == 13 || i == 18 || i == 23;
        if (dash ? a[i] != '-' : strchr("0123456789abcdef", a[i]) == NULL)
            return false;
    }
    return true;
}

static int ms_failures_command_id(void)
{
    int failures = 0;
    char a[MUSE_COMMAND_ID_MAX] = {0}, b[MUSE_COMMAND_ID_MAX] = {0};
    MS_CHECK("command_id refuses a NULL buffer", !muse_session_command_id(NULL));
    MS_CHECK("command_id mints a lowercase UUID-shaped, version-7, "
             "variant-10 handle", muse_session_command_id(a) && strlen(a) == 36);
    MS_CHECK("command_id layout", mx_uuid_shaped(a) && a[14] == '7' &&
             strchr("89ab", a[19]) != NULL);
    MS_CHECK("command_id two handles differ in their random tail",
        muse_session_command_id(b) && strcmp(a + 24, b + 24) != 0);
    return failures;
}

int test_muse_session(void)
{
    int failures = 0;
    failures += ms_failures_journey();
    failures += ms_failures_model_selection(false);
    failures += ms_failures_model_selection(true);
    failures += ms_failures_retry();
    failures += ms_failures_refusals();
    failures += ms_failures_not_loaded();
    failures += ms_failures_prefix();
    failures += ms_failures_boundary();
    failures += ms_failures_usage_settlement(FAKE_USAGE_MATCH);
    failures += ms_failures_usage_settlement(FAKE_USAGE_MISMATCH);
    failures += ms_failures_usage_settlement(FAKE_USAGE_TERMINAL);
    failures += ms_failures_read_line();
    failures += ms_failures_raw_id();
    failures += ms_failures_send();
    failures += ms_failures_stdout_closed();
    failures += ms_failures_command_id();
    if (failures == 0) printf("muse_session: all groups green\n");
    return failures;
}

#endif /* _WIN32 */
