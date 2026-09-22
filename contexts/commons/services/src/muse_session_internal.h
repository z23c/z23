/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: session state shared by the MSP client and the turn-folding
 * translation unit. Not a public header. */
#ifndef ZCL_SERVICES_MUSE_SESSION_INTERNAL_H
#define ZCL_SERVICES_MUSE_SESSION_INTERNAL_H

#include "json/json.h"
#include "services/muse_session.h"

#define MUSE_LINE_MAX (1024u * 1024u)
#define MUSE_WS_MAX 4096u
#define MUSE_TEXT_DEFAULT (64u * 1024u)
#define MUSE_OPEN_DEFAULT_MS 15000
#define MUSE_TURN_DEFAULT_MS 600000
#define MUSE_CLOSE_GRACE_MS 3000

struct muse_session {
    pid_t child;
    int to_child;
    int from_child;
    int next_id;
    int64_t open_timeout_ms;
    int64_t turn_timeout_ms;
    uint64_t max_total_tokens;
    uint64_t tokens_used;
    bool usage_unresolved;
    size_t max_text_bytes;
    char workspace[MUSE_WS_MAX];
    char err[MUSE_ERROR_MAX];
    char kind[64];
    bool retryable;
    /* memory.events "max" at open. -1 when this process has no readable
     * cgroup counter. A later increase means memory.max refused a charge. */
    long long mem_max_events;
    /* Fresh XDG_DATA_HOME for the serve child. Empty when isolation
     * was not armed. Removed after the child is reaped. */
    char data_home[256];
};

void ms_fail(struct muse_session *s, const char *kind, bool retryable,
             const char *fmt, ...);
int64_t ms_monotonic_ms(void);
int ms_read_line(struct muse_session *s, char *buf, size_t cap,
                 int64_t deadline_ms);
bool ms_raw_id(const char *line, char *out, size_t cap);
bool ms_send(struct muse_session *s, int id, const char *method,
             const char *params_json);
bool ms_send_raw(struct muse_session *s, const char *frame);
bool ms_split(struct muse_session *s, const char *line,
              const struct json_value **result_out, struct json_value *doc);
char *ms_await(struct muse_session *s, int id, int64_t deadline_ms);
bool ms_copy_str(char *dst, size_t cap, const char *src);

#endif
