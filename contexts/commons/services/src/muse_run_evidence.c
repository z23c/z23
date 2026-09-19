/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the evidence files one Muse run publishes — receipt.json,
 * muse.json, and the workspace.blocked marker. See header. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "services/muse_run_evidence.h"
#include "services/muse_run.h"
#include "services/muse_run_audit.h"
#include "base/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

bool muse_run_write_atomic(const char *path, const char *text)
{
    char tmp[8192];
    FILE *f;
    size_t n;
    if (!path || !text) return false;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp-%d", path,
            (int)getpid()) >= (int)sizeof(tmp))
        return false;
    f = fopen(tmp, "wb");
    if (!f) return false;
    n = strlen(text);
    if (n > 0 && fwrite(text, 1, n, f) != n) {
        fclose(f);
        (void)unlink(tmp);
        return false;
    }
    if (fclose(f) != 0) {
        (void)unlink(tmp);
        return false;
    }
    if (rename(tmp, path) != 0) {
        (void)unlink(tmp);
        return false;
    }
    return true;
}

void muse_run_write_receipt(const struct muse_run_task *t,
    const struct muse_run_result *r)
{
    char path[8192], body[4096], esc_reason[1024], esc_engine[128];
    muse_json_escape(r->reason, esc_reason, sizeof(esc_reason));
    muse_json_escape(r->engine, esc_engine, sizeof(esc_engine));
    if (snprintf(path, sizeof(path), "%s/receipt.json",
            t->rundir) >= (int)sizeof(path))
        return;
    (void)snprintf(body, sizeof(body),
        "{\"verdict\":\"%s\",\"seq\":%lld,\"name\":\"%s\",\"attempt\":%lld,"
        "\"group\":\"%s\",\"turn\":\"%s\",\"reason\":\"%s\","
        "\"engine\":\"%s\",\"tokens\":%llu,\"files_changed\":%lld,"
        "\"workspace_restored\":%s,\"workspace_blocked\":%s}",
        r->verdict, t->ref.seq, t->ref.name, t->ref.attempt, t->gate,
        r->terminal, esc_reason, esc_engine,
        r->total_tokens, r->files_changed,
        r->workspace_restored ? "true" : "false",
        r->workspace_blocked ? "true" : "false");
    (void)muse_run_write_atomic(path, body);
}

void muse_run_write_facts(const struct muse_run_task *t,
    const struct muse_run_result *r)
{
    char path[8192];
    char *body = zcl_malloc(65536, "muse_run.facts");
    char esc_reason[1024], esc_engine[128], esc_verdict[2048];
    char esc_model[512], esc_gate[512], esc_spawn[192];
    char esc_restore[512], esc_cnote[512];
    if (!body) return;
    muse_json_escape(r->candidate_note, esc_cnote, sizeof(esc_cnote));
    muse_json_escape(r->gate_spawn, esc_spawn, sizeof(esc_spawn));
    muse_json_escape(r->workspace_restore, esc_restore, sizeof(esc_restore));
    muse_json_escape(r->reason, esc_reason, sizeof(esc_reason));
    muse_json_escape(r->engine, esc_engine, sizeof(esc_engine));
    muse_json_escape(r->gate_verdict, esc_verdict, sizeof(esc_verdict));
    muse_json_escape(r->model_resolved, esc_model, sizeof(esc_model));
    muse_json_escape(t->gate, esc_gate, sizeof(esc_gate));
    if (snprintf(path, sizeof(path), "%s/muse.json",
            t->rundir) >= (int)sizeof(path)) {
        free(body);
        return;
    }
    (void)snprintf(body, 65536,
        "{\"ref\":{\"seq\":%lld,\"name\":\"%s\",\"attempt\":%lld},"
        "\"worker\":\"%s\",\"group\":\"%s\",\"scope\":\"%s\","
        "\"model_requested\":\"%s\",\"model_resolved\":\"%s\","
        "\"provider\":\"%s\",\"session\":\"%s\",\"turn\":\"%s\","
        "\"commands\":{\"start\":\"%s\",\"turn\":\"%s\"},"
        "\"terminal\":\"%s\",\"verdict\":\"%s\",\"rc\":%d,"
        "\"reason\":\"%s\",\"engine\":\"%s\","
        "\"base\":\"%s\",\"candidate\":\"%s\","
        "\"candidate_file\":\"%s\",\"candidate_note\":\"%s\","
        "\"head\":{\"pinned\":\"%s\",\"observed\":\"%s\","
        "\"measured\":%s},"
        "\"gate\":{\"name\":\"%s\",\"evidence\":\"%s\","
        "\"verdict\":\"%s\",\"present\":%s,\"ran\":%lld,\"failed\":%lld,"
        "\"ms\":%lld,\"spawn\":\"%s\",\"exit\":%d,\"normal\":%s,"
        "\"build\":{\"target\":\"%s\",\"spawn\":\"%s\",\"ms\":%lld,"
        "\"runner_sha3\":\"%s\"}},"
        "\"tokens\":{\"input\":%llu,\"output\":%llu,\"total\":%llu,"
        "\"cached\":%llu,\"billed\":%llu},"
        "\"duration_ms\":%lld,\"wall_ms\":%lld,\"files_changed\":%lld,"
        "\"scope_audit\":{\"pre_measured\":%s,\"pre_clean\":%s,"
        "\"pre_count\":%lld,\"pre\":[%s],\"changed_measured\":%s,"
        "\"changed_count\":%lld,\"changed\":[%s],"
        "\"outside_count\":%lld,\"outside\":[%s]},"
        "\"prior_unresolved\":%s,"
        "\"workspace\":{\"restored\":%s,\"blocked\":%s,"
        "\"reason\":\"%s\"}}",
        t->ref.seq, t->ref.name, t->ref.attempt,
        t->worker, esc_gate, t->scope,
        t->model, esc_model,
        r->provider, r->session, r->turn,
        r->start_command, r->turn_command,
        r->terminal, r->verdict, r->rc,
        esc_reason, esc_engine,
        r->base, r->candidate,
        r->candidate_file, esc_cnote,
        r->base, r->head_observed,
        r->head_measured ? "true" : "false",
        esc_gate, r->gate_evidence,
        esc_verdict, r->gate_present ? "true" : "false",
        r->gate_ran, r->gate_failed, r->gate_ms,
        esc_spawn, r->gate_exit, r->gate_normal ? "true" : "false",
        MUSE_RUN_GATE_BUILD_TARGET, r->build_spawn, r->build_ms, r->gate_runner,
        r->input_tokens, r->output_tokens, r->total_tokens,
        r->cached_input_tokens, r->billed_tokens,
        r->duration_ms, r->wall_ms, r->files_changed,
        r->scope_pre_measured ? "true" : "false",
        r->scope_pre_clean ? "true" : "false",
        r->scope_pre_count, r->scope_pre,
        r->scope_changed_measured ? "true" : "false",
        r->scope_changed_count, r->scope_changed,
        r->scope_outside_count, r->scope_outside,
        r->prior_unresolved ? "true" : "false",
        r->workspace_restored ? "true" : "false",
        r->workspace_blocked ? "true" : "false", esc_restore);
    (void)muse_run_write_atomic(path, body);
    free(body);
}

/* THE LOUD HALF OF A BLOCKED RESTORE. A half-undone workspace is not a
 * detail of one run's evidence file: it is a workspace the NEXT claimed
 * task must not be handed. The run cannot un-hand it — the receiver's
 * clean-pre-state refusal is what does that, and it is correct — but it
 * can leave the one artifact an operator needs to clear it: what was
 * touched, which base it was going back to, which artifact holds the
 * change, and what stopped. One file, named, beside the evidence. */
void muse_run_write_blocked(const struct muse_run_task *t,
    const struct muse_run_result *r)
{
    char path[8192], body[2048];
    if (snprintf(path, sizeof(path), "%s/workspace.blocked",
            t->rundir) >= (int)sizeof(path))
        return;
    (void)snprintf(body, sizeof(body),
        "workspace=%s\nbase=%s\ncandidate=%s\nref=%lld/%s/%lld\n"
        "blocker=%s\n",
        t->workspace, r->base,
        r->candidate_file[0] ? r->candidate_file : "none",
        t->ref.seq, t->ref.name, t->ref.attempt, r->workspace_restore);
    (void)muse_run_write_atomic(path, body);
}
