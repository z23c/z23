/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The words a refused local board or wiki write is answered with:
 * the fixed refusal phrase plus the limit hit and the command that clears it. */

#include "config/boot_fleet_board.h"
#include "config/mesh_stream.h"

#include "util/log_macros.h"

#include <stdio.h>

/* A refusal of this node's own write: the fixed phrase plus what clears it.
 * Remote peers never see these hints; the phrase alone is the wire text. */
static const char *write_hint(enum fleet_board_result r, char *buf, size_t cap)
{
    switch (r) {
    case FLEET_BOARD_ERR_ROLE:
        return "admit the writer key with: z23 fleet roles grant --fp=<64-hex "
               "key fingerprint> --role=worker";
    case FLEET_BOARD_ERR_WIKI_QUOTA:
        (void)snprintf(buf, cap, "this node's key may write %d wiki revisions "
            "per %d seconds, and a node replaces at most %d superseded revisions "
            "per %d seconds; retry after the window clears",
            (int)FLEET_BOARD_WIKI_QUOTA_WINDOW_MAX,
            (int)FLEET_BOARD_PUBLIC_QUOTA_WINDOW_SECONDS,
            (int)FLEET_BOARD_WIKI_EVICT_MAX, (int)FLEET_BOARD_WIKI_EVICT_SECONDS);
        return buf;
    case FLEET_BOARD_ERR_QUOTA:
        (void)snprintf(buf, cap, "this node's key may post %d messages per %d "
            "seconds and keep %d stored; retry after the window clears",
            (int)FLEET_BOARD_PUBLIC_QUOTA_WINDOW_MAX,
            (int)FLEET_BOARD_PUBLIC_QUOTA_WINDOW_SECONDS,
            (int)FLEET_BOARD_PUBLIC_QUOTA_STORED_MAX);
        return buf;
    case FLEET_BOARD_ERR_WIKI_FULL:
        (void)snprintf(buf, cap, "this node's key holds %d wiki revisions and "
            "none is superseded; revise an existing page (same slug) instead of "
            "adding a new one, or write the page from another node",
            (int)FLEET_BOARD_WIKI_QUOTA_STORED_MAX);
        return buf;
    case FLEET_BOARD_ERR_SIGNATURE:
        return "this node could not sign with its identity key; the node log "
               "names the cause";
    default:
        return NULL;
    }
}

const char *boot_fleet_board_write_message(enum fleet_board_result r, char *buf, size_t cap)
{
    char hint_buf[256];
    const char *hint = write_hint(r, hint_buf, sizeof(hint_buf));
    if (hint)
        (void)snprintf(buf, cap, "%s; %s", fleet_board_result_string(r), hint);
    else
        (void)snprintf(buf, cap, "%s", fleet_board_result_string(r));
    return buf;
}

/* ── the stage a replication refusal happened at ─────────────────────────
 * Every refusal on the pull path names the stage that said no and one
 * command an operator can run. Naming only: nobody is admitted or refused
 * differently because of anything below. */

struct board_stage_words {
    const char *name;
    const char *action;
};

static const struct board_stage_words board_stages[BOARD_STAGES] = {
    [BOARD_STAGE_PAIRING] = {"pairing",
        "inspect the pairing window with `z23 ops mesh pair list`"},
    [BOARD_STAGE_DELEGATION] = {"delegation",
        "inspect delegation and expiry with `z23 fleet doctor` on the peer"},
    [BOARD_STAGE_STREAM] = {"stream",
        "inspect pairing with `z23 ops mesh pair list` and the refusal log on the peer"},
    [BOARD_STAGE_ANSWER_ROLE] = {"answer-role",
        "inspect the role of the asking key on the answering host with `z23 fleet roles list`"},
    [BOARD_STAGE_INGEST_ROLE] = {"ingest-role",
        "inspect the role of the signing key on the receiving host with `z23 fleet roles list`"},
    [BOARD_STAGE_INGEST_LIMIT] = {"ingest-limit",
        "inspect board counts with `z23 fleet board status` and the node storage logs"},
    [BOARD_STAGE_INGEST_STORAGE] = {"ingest-storage",
        "inspect the receiving board store and node storage logs"},
    [BOARD_STAGE_DECODE] = {"decode",
        "inspect build identities on both hosts with `z23 version`"},
    [BOARD_STAGE_ROSTER] = {"roster",
        "inspect membership and roster state with `z23 fleet doctor`"},
    [BOARD_STAGE_CLOCK] = {"clock",
        "inspect sender and receiver clocks and the signed timestamp"},
};

static const struct board_stage_words *board_stage_words(enum boot_fleet_board_stage s)
{
    static const struct board_stage_words unknown = {"unknown", ""};
    return (unsigned)s < BOARD_STAGES ? &board_stages[s] : &unknown;
}

const char *boot_fleet_board_stage_name(enum boot_fleet_board_stage s)
{
    return board_stage_words(s)->name;
}

const char *boot_fleet_board_stage_action(enum boot_fleet_board_stage s)
{
    return board_stage_words(s)->action;
}

const char *boot_fleet_board_stage_line(enum boot_fleet_board_stage s,
                                        const char *detail, char *buf,
                                        size_t cap)
{
    (void)snprintf(buf, cap, "stage=%s: %s; next: %s",
                   boot_fleet_board_stage_name(s), detail ? detail : "",
                   boot_fleet_board_stage_action(s));
    return buf;
}

enum boot_fleet_board_stage boot_fleet_board_ingest_stage(
    enum fleet_board_result r)
{
    switch (r) {
    case FLEET_BOARD_ERR_ROLE:
        return BOARD_STAGE_INGEST_ROLE;
    case FLEET_BOARD_ERR_FUTURE:
        return BOARD_STAGE_CLOCK;
    case FLEET_BOARD_ERR_QUOTA:
    case FLEET_BOARD_ERR_WIKI_QUOTA:
    case FLEET_BOARD_ERR_WIKI_FULL:
    case FLEET_BOARD_ERR_CAPACITY:
    case FLEET_BOARD_ERR_BUSY:
        return BOARD_STAGE_INGEST_LIMIT;
    case FLEET_BOARD_ERR_STORAGE:
        return BOARD_STAGE_INGEST_STORAGE;
    default:
        return BOARD_STAGE_DECODE;
    }
}

static bool stage_of_gate(int reason, enum boot_fleet_board_stage *out)
{
    switch ((enum boot_fleet_board_gate_reason)reason) {
    case FLEET_BOARD_GATE_PAIRING:
        *out = BOARD_STAGE_PAIRING;
        return true;
    case FLEET_BOARD_GATE_DELEGATION_UNRESOLVED:
    case FLEET_BOARD_GATE_DELEGATION_REFUSED:
        *out = BOARD_STAGE_DELEGATION;
        return true;
    case FLEET_BOARD_GATE_ROSTER:
        *out = BOARD_STAGE_ROSTER;
        return true;
    }
    return false;
}

bool boot_fleet_board_observation_stage(
    const struct boot_fleet_board_observation *v,
    enum boot_fleet_board_stage *out)
{
    if (!v || !v->found || !out)
        return false;
    switch (v->phase) {
    case FLEET_BOARD_OBS_GATE:
        return stage_of_gate(v->result, out);
    case FLEET_BOARD_OBS_ANSWER_REFUSED:
        *out = BOARD_STAGE_DECODE;
        return true;
    case FLEET_BOARD_OBS_ANSWER_DEFERRED:
        *out = BOARD_STAGE_INGEST_LIMIT;
        return true;
    case FLEET_BOARD_OBS_OPEN_FAILURE:
        *out = BOARD_STAGE_STREAM;
        return true;
    case FLEET_BOARD_OBS_CLOSE:
        /* A finished or service-ended stream is not a refusal. */
        *out = BOARD_STAGE_STREAM;
        return v->result != 0 && v->result != MESH_STREAM_CLOSED_BY_SERVICE;
    case FLEET_BOARD_OBS_INGEST:
        if (v->stored || v->result == FLEET_BOARD_OK ||
            v->result == FLEET_BOARD_ERR_EXPIRED)
            return false; /* stored, held, or stale: not a refusal */
        *out = boot_fleet_board_ingest_stage((enum fleet_board_result)v->result);
        return true;
    default:
        return false;
    }
}

const char *boot_fleet_board_ingest_line(enum fleet_board_result r, char *buf,
                                         size_t cap)
{
    return boot_fleet_board_stage_line(boot_fleet_board_ingest_stage(r),
                                       fleet_board_result_string(r), buf, cap);
}

void boot_fleet_board_stage_warn(const char *what,
                                 enum boot_fleet_board_stage s,
                                 const char *detail)
{
    char line[512];
    LOG_WARN("fleet.board", "%s: %s", what,
             boot_fleet_board_stage_line(s, detail, line, sizeof line));
}

void boot_fleet_board_ingest_warn(const char *what, enum fleet_board_result r)
{
    boot_fleet_board_stage_warn(what, boot_fleet_board_ingest_stage(r),
                                fleet_board_result_string(r));
}

const char *boot_fleet_board_deferred_line(enum fleet_board_result r,
                                           bool roster_only, char *buf,
                                           size_t cap)
{
    if (roster_only && r == FLEET_BOARD_ERR_ROLE)
        return boot_fleet_board_stage_line(
            BOARD_STAGE_ROSTER, "this box takes only sealed rows until "
            "they arm its roster", buf, cap);
    return boot_fleet_board_ingest_line(r, buf, cap);
}
