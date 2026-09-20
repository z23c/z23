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
    if (failures == 0) printf("muse_session: all groups green\n");
    return failures;
}

#endif /* _WIN32 */
