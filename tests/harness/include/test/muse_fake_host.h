/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: one scripted in-process MSP host shared by the muse worker
 * tests. A forked child speaks framed MSP JSON-RPC with canned answers
 * and reports everything it saw back over an evidence pipe, so no check
 * can pass vacuously. Header-only with static linkage: each including
 * test TU gets its own copy and no symbols collide.
 */
#ifndef ZCL_TEST_MUSE_FAKE_HOST_H
#define ZCL_TEST_MUSE_FAKE_HOST_H

#include "services/muse_session.h"
#if !defined(_WIN32)
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* --- scripted fake host ------------------------------------------------- */

enum fake_mode {
    FAKE_JOURNEY,   /* full turn with approvals + input + usage + terminal */
    FAKE_RETRY,     /* turn/start twice with one command id */
    FAKE_HANDSHAKE, /* initialize only; used for client-side refusals */
    FAKE_NOT_LOADED,/* turn/start answers sessionNotLoaded */
    FAKE_PREFIX,    /* eight approval probes + terminal usage finalize */
    FAKE_CANCELLED, /* turn completes at once with terminal cancelled */
    FAKE_UNKNOWN,   /* journey plus an unknown-method notification mid-turn */
    FAKE_GARBAGE,   /* journey then a malformed line instead of terminal */
    FAKE_EXIT,      /* host exits right after the turn is accepted */
    FAKE_USAGE_MATCH,
    FAKE_USAGE_MISMATCH,
    FAKE_USAGE_TERMINAL,
    FAKE_HANG       /* turn accepted, then silence until the client leaves */
};

/* Model the session/start answer resolves; tests reprogram it to prove a
 * substitution stays visible instead of silent. */
static const char *s_fake_model = "m-test";

static int s_evidence_fd = -1;

/* Scripted per-turn usage triple; the boundary tests reprogram it. */
static long s_use_in = 10;
static long s_use_out = 5;
static long s_use_total = 15;
static long s_use_cached = 0; /* >0 adds usage cacheReadTokens */
static bool s_use_cumulative = false;
static long s_cumulative_turns = 0;

static void fake_note(const char *fmt, const char *a, const char *b)
{
    if (s_evidence_fd < 0) return;
    char buf[1024];
    int n = snprintf(buf, sizeof(buf), fmt, a ? a : "", b ? b : "");
    if (n > 0) {
        (void)write(s_evidence_fd, buf, (size_t)n);
        (void)write(s_evidence_fd, "\n", 1);
    }
}

/* One absolute path the scripted turn creates in the claimed workspace;
 * "" writes nothing. The executor measures the workspace AFTER the turn,
 * so a case that wants a real post-turn change must have the TURN make it:
 * dirtying the workspace beforehand is baseline dirt, which the executor
 * now refuses on purpose before spending a token. */
static char s_fake_write_path[4096] = "";

/* mkdir -p over the parent directories of an absolute path. */
static void fake_mkdirs(const char *path)
{
    char tmp[4096];
    if (snprintf(tmp, sizeof(tmp), "%s", path) >= (int)sizeof(tmp)) return;
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        (void)mkdir(tmp, 0755);
        *p = '/';
    }
}

/* The turn's own edit, laid down after the turn is accepted and before any
 * terminal: exactly where a real model's write would land. */
static void fake_turn_write(void)
{
    FILE *f;
    if (!s_fake_write_path[0]) return;
    fake_mkdirs(s_fake_write_path);
    f = fopen(s_fake_write_path, "wb");
    if (!f) {
        fake_note("write-failed:%s", s_fake_write_path, "");
        return;
    }
    (void)fputs("the turn wrote this\n", f);
    (void)fclose(f);
    fake_note("wrote:%s", s_fake_write_path, "");
}

static bool fake_gets(FILE *in, char *buf, size_t cap)
{
    if (!fgets(buf, (int)cap, in)) return false;
    buf[strcspn(buf, "\r\n")] = '\0';
    return true;
}

static void fake_send(FILE *out, const char *frame)
{
    fputs(frame, out);
    fputc('\n', out);
    fflush(out);
}

/* Copies the top-level string member `key` ("k":"v") into out. */
static bool fake_str(const char *line, const char *key, char *out, size_t cap)
{
    char pat[128];
    (void)snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    const char *p = strstr(line, pat);
    if (!p || cap == 0) return false;
    p += strlen(pat);
    size_t n = 0;
    while (*p && *p != '"' && n + 1 < cap) out[n++] = *p++;
    out[n] = '\0';
    return *p == '"';
}

static long fake_id(const char *line)
{
    const char *p = strstr(line, "\"id\":");
    return p ? strtol(p + 5, NULL, 10) : -1;
}

static void fake_result(FILE *out, long id, const char *result_json)
{
    char frame[4096];
    (void)snprintf(frame, sizeof(frame),
        "{\"jsonrpc\":\"2.0\",\"id\":%ld,\"result\":%s}", id, result_json);
    fake_send(out, frame);
}

static void fake_error(FILE *out, long id, int code, const char *kind,
    bool retryable, const char *message)
{
    char frame[2048];
    (void)snprintf(frame, sizeof(frame),
        "{\"jsonrpc\":\"2.0\",\"id\":%ld,\"error\":{\"code\":%d,"
        "\"message\":\"%s\",\"data\":{\"kind\":\"%s\",\"retryable\":%s}}}",
        id, code, message, kind, retryable ? "true" : "false");
    fake_send(out, frame);
}

/* Reads lines until `method` arrives; answers nothing meanwhile. */
static bool fake_until(FILE *in, const char *method, char *line, size_t cap)
{
    for (;;) {
        if (!fake_gets(in, line, cap)) return false;
        if (strstr(line, method)) return true;
    }
}

/* Serves one journey turn: two approvals (path allow, shell deny), one
 * declined user-input prompt, deltas, usage and the terminal record.
 * tail != 0 replaces the terminal record with a malformed line and
 * closes the stream: the client must fail closed, never pass. */
static void fake_journey_turn(FILE *in, FILE *out, const char *session,
    const char *turn_cmd, int tail)
{
    char tid[128];
    (void)snprintf(tid, sizeof(tid), "%s", turn_cmd);
    char frame[4096];
    (void)snprintf(frame, sizeof(frame),
        "{\"jsonrpc\":\"2.0\",\"method\":\"turn/started\","
        "\"params\":{\"sessionId\":\"%s\",\"turnId\":\"%s\"}}", session, tid);
    fake_send(out, frame);
    /* Approval 1: workspace file under the allowlisted prefix. */
    (void)snprintf(frame, sizeof(frame),
        "{\"jsonrpc\":\"2.0\",\"id\":900,\"method\":\"approval/request\","
        "\"params\":{\"approvalId\":\"ap-1\",\"sessionId\":\"%s\","
        "\"turnId\":\"%s\",\"itemId\":\"it-1\",\"toolCallId\":\"tc-1\","
        "\"toolName\":\"write\",\"currentRequirementId\":7,"
        "\"judgeEscalated\":false,\"protectedWrite\":false,"
        "\"rawArgs\":\"{}\",\"taskId\":\"t-1\","
        "\"subject\":{\"kind\":\"fileAccess\",\"path\":"
        "\"/z23-muse-test/ws/notes/todo.txt\"},"
        "\"availableChoices\":[{\"choiceId\":\"c-allow\","
        "\"decision\":\"approved\",\"label\":\"Allow\",\"scope\":\"once\","
        "\"acceptsFeedback\":false},{\"choiceId\":\"c-deny\","
        "\"decision\":\"denied\",\"label\":\"Deny\",\"scope\":\"once\","
        "\"acceptsFeedback\":true}]}}",
        session, tid);
    fake_send(out, frame);
    /* Approval 2: hostile shell, numeric requirement id as a string. */
    (void)snprintf(frame, sizeof(frame),
        "{\"jsonrpc\":\"2.0\",\"id\":901,\"method\":\"approval/request\","
        "\"params\":{\"approvalId\":\"ap-2\",\"sessionId\":\"%s\","
        "\"turnId\":\"%s\",\"itemId\":\"it-2\",\"toolCallId\":\"tc-2\","
        "\"toolName\":\"shell\",\"currentRequirementId\":\"req-s2\","
        "\"judgeEscalated\":false,\"protectedWrite\":false,"
        "\"rawArgs\":\"{}\",\"taskId\":\"t-1\","
        "\"subject\":{\"kind\":\"shell\",\"command\":\"rm -rf /\"},"
        "\"availableChoices\":[{\"choiceId\":\"c-allow\","
        "\"decision\":\"approved\",\"label\":\"Allow\",\"scope\":\"once\","
        "\"acceptsFeedback\":false},{\"choiceId\":\"c-deny\","
        "\"decision\":\"denied\",\"label\":\"Deny\",\"scope\":\"once\","
        "\"acceptsFeedback\":true}]}}",
        session, tid);
    fake_send(out, frame);
    (void)snprintf(frame, sizeof(frame),
        "{\"jsonrpc\":\"2.0\",\"id\":902,\"method\":\"userInput/request\","
        "\"params\":{\"sessionId\":\"%s\",\"userInputId\":\"ui-1\"}}",
        session);
    fake_send(out, frame);
    /* Consume the three decides/cancels plus their receipts. */
    char line[65536];
    int decisions = 0, receipts = 0;
    while (decisions < 3 || receipts < 3) {
        if (!fake_gets(in, line, sizeof(line))) break;
        if (strstr(line, "\"method\":\"approval/decide\"")) {
            char choice[64] = {0}, req[256] = {0};
            fake_str(line, "choiceId", choice, sizeof(choice));
            const char *rp = strstr(line, "\"requirementId\":");
            if (rp) {
                rp += strlen("\"requirementId\":");
                size_t k = 0;
                while (*rp && *rp != ',' && *rp != '}' &&
                    k + 1 < sizeof(req))
                    req[k++] = *rp++;
                req[k] = '\0';
            }
            fake_note("decide:%s:%s", choice, req);
            decisions++;
        } else if (strstr(line, "\"method\":\"userInput/cancel\"")) {
            fake_note("declined:%s", "ui-1", "");
            decisions++;
        } else if (strstr(line, "\"result\":{}")) {
            receipts++;
        }
    }
    (void)snprintf(frame, sizeof(frame),
        "{\"jsonrpc\":\"2.0\",\"method\":\"item/delta\","
        "\"params\":{\"sessionId\":\"%s\",\"turnId\":\"%s\","
        "\"itemId\":\"m-1\",\"field\":\"text\",\"delta\":\"hel\"}}",
        session, tid);
    fake_send(out, frame);
    (void)snprintf(frame, sizeof(frame),
        "{\"jsonrpc\":\"2.0\",\"method\":\"item/delta\","
        "\"params\":{\"sessionId\":\"%s\",\"turnId\":\"%s\","
        "\"itemId\":\"m-1\",\"field\":\"text\",\"delta\":\"lo\"}}",
        session, tid);
    fake_send(out, frame);
    (void)snprintf(frame, sizeof(frame),
        "{\"jsonrpc\":\"2.0\",\"method\":\"item/completed\","
        "\"params\":{\"sessionId\":\"%s\",\"item\":{\"itemId\":\"m-1\","
        "\"kind\":\"agentMessage\",\"turnId\":\"%s\",\"text\":\"fake-ok\"}}}",
        session, tid);
    fake_send(out, frame);
    /* The same reading is delivered twice under one cursor: the adapter
     * must fold it exactly once. */
    char cumulative[256] = "";
    if (s_use_cumulative) {
        s_cumulative_turns++;
        (void)snprintf(cumulative, sizeof(cumulative),
            ",\"cumulative\":{\"promptTokens\":%ld,"
            "\"outputTokens\":%ld,\"totalTokens\":%ld}",
            s_use_in * s_cumulative_turns,
            s_use_out * s_cumulative_turns,
            s_use_total * s_cumulative_turns);
    }
    for (int dup = 0; dup < 2; dup++) {
        (void)snprintf(frame, sizeof(frame),
            "{\"jsonrpc\":\"2.0\",\"method\":\"session/tokenUsage\","
            "\"params\":{\"sessionId\":\"%s\",\"turnId\":\"%s\","
            "\"viewCursor\":\"v:9\","
            "\"usage\":{\"inputTokens\":%ld,\"outputTokens\":%ld,"
            "\"cacheReadTokens\":%ld},"
            "\"promptTokens\":%ld,\"totalTokens\":%ld%s}}",
            session, tid, s_use_in, s_use_out, s_use_cached, s_use_in,
            s_use_total, cumulative);
        fake_send(out, frame);
    }
    if (!tail) {
        (void)snprintf(frame, sizeof(frame),
            "{\"jsonrpc\":\"2.0\",\"method\":\"turn/completed\","
            "\"params\":{\"sessionId\":\"%s\",\"turnId\":\"%s\","
            "\"terminal\":\"completed\",\"durationMs\":7}}",
            session, tid);
        fake_send(out, frame);
        return;
    }
    fputs("this line is not JSON-RPC\n", out);
    fflush(out);
    fclose(out);
    _exit(0);
}

/* Eight approval probes: descendant, exact file, sibling-prefix attack,
 * dot-dot escape, outside-root absolute, workspace-relative, listed shell
 * command, unlisted shell command. */
static const char *prefix_subjects[8] = {
    "{\"kind\":\"fileAccess\",\"path\":\"/z23-muse-test/ws/notes/todo.txt\"}",
    "{\"kind\":\"fileAccess\",\"path\":\"/z23-muse-test/ws/src/sum.c\"}",
    "{\"kind\":\"fileAccess\",\"path\":\"/z23-muse-test/ws/notes2/evil.txt\"}",
    "{\"kind\":\"fileAccess\",\"path\":\"/z23-muse-test/ws/notes/../evil.txt\"}",
    "{\"kind\":\"fileAccess\",\"path\":\"/etc/passwd\"}",
    "{\"kind\":\"fileAccess\",\"path\":\"notes/todo.txt\"}",
    "{\"kind\":\"shell\",\"command\":\"cc -o sum_test\"}",
    "{\"kind\":\"shell\",\"command\":\"rm -rf /\"}",
};

static void fake_prefix_turn(FILE *in, FILE *out, const char *session,
    const char *tid)
{
    char frame[4096], line[65536];
    for (int i = 0; i < 8; i++) {
        (void)snprintf(frame, sizeof(frame),
            "{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"approval/request\","
            "\"params\":{\"approvalId\":\"ap-%d\",\"sessionId\":\"%s\","
            "\"turnId\":\"%s\",\"itemId\":\"it-%d\",\"toolCallId\":\"tc-%d\","
            "\"toolName\":\"t\",\"currentRequirementId\":%s,"
            "\"judgeEscalated\":false,\"protectedWrite\":false,"
            "\"rawArgs\":\"{}\",\"taskId\":\"t-1\",\"subject\":%s,"
            "\"availableChoices\":[{\"choiceId\":\"c-allow\","
            "\"decision\":\"approved\",\"label\":\"Allow\",\"scope\":\"once\","
            "\"acceptsFeedback\":false},{\"choiceId\":\"c-deny\","
            "\"decision\":\"denied\",\"label\":\"Deny\",\"scope\":\"once\","
            "\"acceptsFeedback\":true}]}}",
            900 + i, i, session, tid, i, i,
            i % 2 ? "\"req-s\"" : "7", prefix_subjects[i]);
        fake_send(out, frame);
    }
    int decisions = 0, receipts = 0;
    while (decisions < 8 || receipts < 8) {
        if (!fake_gets(in, line, sizeof(line))) break;
        if (strstr(line, "\"method\":\"approval/decide\"")) {
            char choice[64] = {0};
            fake_str(line, "choiceId", choice, sizeof(choice));
            fake_note("decide:%s", choice, "");
            decisions++;
        } else if (strstr(line, "\"result\":{}")) {
            receipts++;
        }
    }
    (void)snprintf(frame, sizeof(frame),
        "{\"jsonrpc\":\"2.0\",\"method\":\"item/completed\","
        "\"params\":{\"sessionId\":\"%s\",\"item\":{\"itemId\":\"m-1\","
        "\"kind\":\"agentMessage\",\"turnId\":\"%s\","
        "\"text\":\"prefix-ok\"}}}",
        session, tid);
    fake_send(out, frame);
    (void)snprintf(frame, sizeof(frame),
        "{\"jsonrpc\":\"2.0\",\"method\":\"session/tokenUsage\","
        "\"params\":{\"sessionId\":\"%s\",\"turnId\":\"%s\","
        "\"viewCursor\":\"v:p1\","
        "\"usage\":{\"inputTokens\":10,\"outputTokens\":5},"
        "\"totalTokens\":15}}",
        session, tid);
    fake_send(out, frame);
    /* Terminal usage is authoritative: it replaces the 10/5/15 above. */
    (void)snprintf(frame, sizeof(frame),
        "{\"jsonrpc\":\"2.0\",\"method\":\"turn/completed\","
        "\"params\":{\"sessionId\":\"%s\",\"turnId\":\"%s\","
        "\"terminal\":\"completed\",\"durationMs\":3,"
        "\"usage\":{\"inputTokens\":100,\"outputTokens\":50,"
        "\"totalTokens\":160},\"totalTokens\":160}}",
        session, tid);
    fake_send(out, frame);
}

static void fake_usage_turn(FILE *out, const char *sid, const char *tid,
    enum fake_mode mode)
{
    char frame[2048];
    if (mode != FAKE_USAGE_TERMINAL) {
        /* Two unique completions; the second delivery repeats cursor 2. */
        for (int delivery = 0; delivery < 3; delivery++) {
            int n = delivery == 0 ? 1 : 2;
            (void)snprintf(frame, sizeof(frame),
                "{\"jsonrpc\":\"2.0\",\"method\":\"session/tokenUsage\","
                "\"params\":{\"sessionId\":\"%s\",\"turnId\":\"%s\","
                "\"viewCursor\":\"v:usage-%d\",\"promptTokens\":40,"
                "\"sourceRange\":{\"stream\":{\"kind\":\"run\","
                "\"id\":\"usage-run\"},\"first\":{\"id\":\"event-%d\","
                "\"sequence\":%d},\"last\":{\"id\":\"event-%d\","
                "\"sequence\":%d}},"
                "\"totalTokens\":45,\"usage\":{\"inputTokens\":5,"
                "\"outputTokens\":5,\"cachedTokens\":35,"
                "\"cacheReadTokens\":35,\"reasoningTokens\":0},"
                "\"cumulative\":{\"promptTokens\":%d,"
                "\"outputTokens\":%d,\"totalTokens\":%d}}}",
                sid, tid, n, n, n, n, n, 40 * n, 5 * n, 45 * n);
            fake_send(out, frame);
        }
    }
    int raw_input = mode == FAKE_USAGE_MISMATCH ? 11 : 10;
    int cached = mode == FAKE_USAGE_TERMINAL ? 0 : 70;
    (void)snprintf(frame, sizeof(frame),
        "{\"jsonrpc\":\"2.0\",\"method\":\"turn/completed\","
        "\"params\":{\"sessionId\":\"%s\",\"turnId\":\"%s\","
        "\"terminal\":\"completed\",\"usage\":{\"inputTokens\":%d,"
        "\"outputTokens\":10,\"cachedTokens\":%d,"
        "\"cacheReadTokens\":%d,\"reasoningTokens\":0}}}",
        sid, tid, raw_input, cached, cached);
    fake_send(out, frame);
}

static void fake_main(enum fake_mode mode)
{
    /* A failed test closes the transport mid-script; later frames must die
     * as short writes, never as an unreported SIGPIPE kill. */
    (void)signal(SIGPIPE, SIG_IGN);
    char line[65536];
    FILE *in = stdin, *out = stdout;
    if (!fake_until(in, "\"method\":\"initialize\"", line, sizeof(line)))
        _exit(3);
    fake_result(out, fake_id(line),
        "{\"sessionDurability\":\"durable\"}");
    /* initialized notification */
    if (!fake_gets(in, line, sizeof(line))) _exit(3);
    if (mode == FAKE_HANDSHAKE) {
        /* Client-side refusals send nothing further; EOF ends us. */
        while (fake_gets(in, line, sizeof(line))) { }
        _exit(0);
    }
    if (!fake_until(in, "\"method\":\"session/start\"", line, sizeof(line)))
        _exit(3);
    char ws[512] = {0};
    fake_str(line, "workspaceRoot", ws, sizeof(ws));
    fake_note("workspace:%s", ws, "");
    {
        char sess[512];
        (void)snprintf(sess, sizeof(sess),
            "{\"session\":{\"sessionId\":\"sess-test-1\","
            "\"providerId\":\"meta\",\"modelId\":\"%s\"},"
            "\"viewCursor\":\"v:1\"}",
            s_fake_model ? s_fake_model : "m-test");
        fake_result(out, fake_id(line), sess);
    }
    for (;;) {
        if (!fake_gets(in, line, sizeof(line))) break;
        if (strstr(line, "\"method\":\"turn/start\"")) {
            char cmd[128] = {0}, sid[128] = {0};
            fake_str(line, "commandId", cmd, sizeof(cmd));
            fake_str(line, "sessionId", sid, sizeof(sid));
            fake_note("turn-cmd:%s", cmd, "");
            if (mode == FAKE_NOT_LOADED) {
                fake_error(out, fake_id(line), -32024, "sessionNotLoaded",
                    false, "session is not loaded on this host");
                continue;
            }
            char res[512];
            (void)snprintf(res, sizeof(res),
                "{\"commandId\":\"%s\",\"status\":\"accepted\","
                "\"turnId\":\"%s\",\"startedNewTurn\":true,"
                "\"disposition\":\"started\"}",
                cmd, mode == FAKE_RETRY ? "turn-fixed" : cmd);
            fake_result(out, fake_id(line), res);
            /* The turn is live now: its edit lands before any terminal. */
            fake_turn_write();
            if (mode == FAKE_JOURNEY)
                fake_journey_turn(in, out, sid, cmd, 0);
            else if (mode == FAKE_USAGE_MATCH ||
                mode == FAKE_USAGE_MISMATCH || mode == FAKE_USAGE_TERMINAL)
                fake_usage_turn(out, sid, cmd, mode);
            else if (mode == FAKE_UNKNOWN) {
                char unk[512];
                (void)snprintf(unk, sizeof(unk),
                    "{\"jsonrpc\":\"2.0\",\"method\":\"frobnicate/event\","
                    "\"params\":{\"sessionId\":\"%s\"}}",
                    sid);
                fake_send(out, unk);
                fake_journey_turn(in, out, sid, cmd, 0);
            } else if (mode == FAKE_GARBAGE) {
                fake_journey_turn(in, out, sid, cmd, 1);
            } else if (mode == FAKE_EXIT) {
                fflush(out);
                _exit(0);
            } else if (mode == FAKE_HANG) {
                /* Silence: answer a cancel if one arrives, never send a
                 * terminal. The client must time out and cancel first. */
                char hline[65536];
                while (fake_gets(in, hline, sizeof(hline))) {
                    if (strstr(hline, "\"method\":\"turn/cancel\"")) {
                        char tid[128] = {0};
                        fake_str(hline, "turnId", tid, sizeof(tid));
                        fake_note("cancel:%s", tid, "");
                        fake_result(out, fake_id(hline),
                            "{\"status\":\"admitted\"}");
                    }
                }
                _exit(0);
            }
            else if (mode == FAKE_PREFIX)
                fake_prefix_turn(in, out, sid, cmd);
            else if (mode == FAKE_CANCELLED) {
                char done[512];
                (void)snprintf(done, sizeof(done),
                    "{\"jsonrpc\":\"2.0\",\"method\":\"turn/completed\","
                    "\"params\":{\"sessionId\":\"%s\","
                    "\"turnId\":\"%s\",\"terminal\":\"cancelled\"}}",
                    sid, cmd);
                fake_send(out, done);
            }
            else if (mode == FAKE_RETRY) {
                char done[512];
                (void)snprintf(done, sizeof(done),
                    "{\"jsonrpc\":\"2.0\",\"method\":\"turn/completed\","
                    "\"params\":{\"sessionId\":\"%s\","
                    "\"turnId\":\"turn-fixed\",\"terminal\":\"completed\"}}",
                    sid);
                fake_send(out, done);
            }
        } else if (strstr(line, "\"method\":\"turn/cancel\"")) {
            char tid[128] = {0};
            fake_str(line, "turnId", tid, sizeof(tid));
            fake_note("cancel:%s", tid, "");
            fake_result(out, fake_id(line),
                "{\"status\":\"admitted\"}");
        } else if (strstr(line, "\"method\":\"session/setModel\"")) {
            char mid[128] = {0};
            fake_str(line, "modelId", mid, sizeof(mid));
            fake_note("model:%s", mid, "");
            fake_result(out, fake_id(line),
                "{\"status\":\"selected\"}");
        } else if (strstr(line, "\"method\":\"usage/read\"")) {
            fake_result(out, fake_id(line), "{}");
        }
    }
    _exit(0);
}

struct fake_host {
    pid_t child;
    struct muse_session *session;
};

static bool spawn_fake(enum fake_mode mode, int ev_read,
    const struct muse_session_limits *limits, struct fake_host *host)
{
    int to_child[2], from_child[2];
    if (pipe(to_child) != 0 || pipe(from_child) != 0) return false;
    pid_t pid = fork();
    if (pid < 0) {
        close(to_child[0]); close(to_child[1]);
        close(from_child[0]); close(from_child[1]);
        return false;
    }
    if (pid == 0) {
        close(to_child[1]);
        close(from_child[0]);
        close(ev_read);
        (void)dup2(to_child[0], STDIN_FILENO);
        (void)dup2(from_child[1], STDOUT_FILENO);
        close(to_child[0]);
        close(from_child[1]);
        fake_main(mode);
        _exit(0);
    }
    close(to_child[0]);
    close(from_child[1]);
    host->child = pid;
    host->session = muse_session_attach(pid, to_child[1], from_child[0],
        limits);
    if (!host->session) {
        int status = 0;
        (void)waitpid(pid, &status, 0);
        close(to_child[1]);
        close(from_child[0]);
        return false;
    }
    return true;
}

static void close_fake(struct fake_host *host)
{
    muse_session_close(host->session);
    host->session = NULL;
    int status = 0;
    (void)waitpid(host->child, &status, 0);
    host->child = -1;
}

static bool evidence_has(const char *evidence, const char *needle)
{
    return evidence && needle && strstr(evidence, needle) != NULL;
}

static char *read_evidence(int fd)
{
    char *buf = malloc(8192);
    size_t n = 0;
    if (!buf) return NULL;
    buf[0] = '\0';
    ssize_t k;
    while ((k = read(fd, buf + n, 8191 - n)) > 0) {
        n += (size_t)k;
        buf[n] = '\0';
        if (n >= 8191) break;
    }
    return buf;
}

static int evidence_count(const char *evidence, const char *needle)
{
    int hits = 0;
    if (evidence && needle && needle[0]) {
        const char *at = evidence;
        size_t span = strlen(needle);
        while ((at = strstr(at, needle)) != NULL) {
            hits++;
            at += span;
        }
    }
    return hits;
}

#endif /* ZCL_TEST_MUSE_FAKE_HOST_H */
