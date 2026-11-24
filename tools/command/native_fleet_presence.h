/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: internal seam between fleet.steer.presence (post one presence.v1
 *          row) and its hook mode (--hook=start|beat|end,
 *          native_fleet_presence_hook.c) plus the per-role state record
 *          both share. */
#ifndef ZCL_NATIVE_FLEET_PRESENCE_H
#define ZCL_NATIVE_FLEET_PRESENCE_H

#include "command/native_command.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_PRESENCE_FLOOR_S 60
#define ZCL_PRESENCE_BEAT_S 300
#define ZCL_PRESENCE_WINDOW_S 900

struct zcl_presence_in {
    const char *role, *task, *phase, *session, *started, *source, *owner;
    long long pid;
};

/* What the last post for one role left behind (state root, presence/). */
struct zcl_presence_rec {
    char owner[48];
    char started[24];
    char phase[16];
    long long beat; /* epoch seconds of the last accepted post, 0 = none */
};

bool zcl_presence_rec_load(const char *role, struct zcl_presence_rec *rec);
bool zcl_presence_rec_store(const char *role,
                            const struct zcl_presence_rec *rec);

/* Post one row for in->role: validates, applies the per-role floor, records
 * state. A repeat of the same role and phase inside the floor is answered as
 * a passed no-op with skipped=true. */
void zcl_presence_emit(const struct zcl_command_request *req,
                       struct zcl_command_reply *reply,
                       const struct zcl_presence_in *in);
void zcl_presence_reply_skipped(struct zcl_command_reply *reply,
                                const char *role, const char *why);
void zcl_presence_fail(struct zcl_command_reply *reply, const char *code,
                       const char *message, const char *evidence);
const char *zcl_presence_str(const struct zcl_command_request *req,
                             const char *key);
bool zcl_presence_pid_in(const struct zcl_command_request *req, long long *pid);

/* Hook mode never fails: it silences the refusal log (the hook log file
 * records it instead). */
void zcl_presence_quiet(bool on);

/* The --hook=<mode> path. */
void zcl_presence_hook(const struct zcl_command_request *req,
                       struct zcl_command_reply *reply, const char *mode);

#endif
