/* zlog — small leveled logging sink (C23).
 *
 * Levels, per-sink thresholds, caller-injected output callback, and
 * printf-free message building. A sink formats
 * "LEVEL tag message\n" through bounded cursor operations; long
 * messages are truncated, never overrun.
 *
 * Apache-2.0 licensed. No dependencies beyond libc.
 */
#ifndef ZLOG_H
#define ZLOG_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ZLOG_TRACE = 0,
    ZLOG_DEBUG = 1,
    ZLOG_INFO  = 2,
    ZLOG_WARN  = 3,
    ZLOG_ERROR = 4,
    ZLOG_OFF   = 5
} zlog_level;

typedef struct {
    /* Receives fully formatted lines (NUL-terminated). May be NULL to
     * sink into /dev/null. */
    void (*emit)(void *ctx, const char *line);
    void *ctx;
    zlog_level threshold;
    bool include_tag;
    const char *tag;      /* e.g. subsystem name; may be NULL */
} zlog_sink;

/* Emit one line when level >= threshold. Message is built by the
 * caller (use zfmt or plain strings). Returns true when emitted. */
bool zlog_write(const zlog_sink *sink, zlog_level level, const char *message);

/* Convenience wrappers. */
bool zlog_trace(const zlog_sink *sink, const char *msg);
bool zlog_debug(const zlog_sink *sink, const char *msg);
bool zlog_info(const zlog_sink *sink, const char *msg);
bool zlog_warn(const zlog_sink *sink, const char *msg);
bool zlog_error(const zlog_sink *sink, const char *msg);

/* Level name ("TRACE".."ERROR") and parsing (case-insensitive;
 * ZLOG_OFF on unknown). */
const char *zlog_level_name(zlog_level level);
zlog_level  zlog_level_parse(const char *s);

#ifdef __cplusplus
}
#endif

#endif /* ZLOG_H */
