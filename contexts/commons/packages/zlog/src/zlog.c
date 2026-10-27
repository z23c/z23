#include "zlog/zlog.h"

#include <string.h>

#define ZLOG_LINE_CAP 256

static const char *const NAMES[5] = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR"};

const char *zlog_level_name(zlog_level level)
{
    if (level < ZLOG_TRACE || level > ZLOG_ERROR) return "OFF";
    return NAMES[level];
}

zlog_level zlog_level_parse(const char *s)
{
    if (!s) return ZLOG_OFF;
    for (int i = 0; i < 5; i++) {
        const char *n = NAMES[i];
        size_t j = 0;
        while (n[j] && s[j]) {
            char c = s[j];
            if (c >= 'a' && c <= 'z') c -= 32;
            if (c != n[j]) break;
            j++;
        }
        if (!n[j] && !s[j]) return (zlog_level)i;
    }
    if (strcmp(s, "off") == 0 || strcmp(s, "OFF") == 0) return ZLOG_OFF;
    return ZLOG_OFF;
}

/* Append the level name, truncated to fit the line, advancing the cursor. */
static void zlog_append_level_name(char *line, size_t *o, zlog_level level)
{
    const char *name = zlog_level_name(level);
    size_t nl = strlen(name);
    if (nl > ZLOG_LINE_CAP - 2) nl = ZLOG_LINE_CAP - 2;
    memcpy(line + *o, name, nl);
    *o += nl;
}

/* Append a separating space when the line still has room, advancing the cursor. */
static void zlog_append_space(char *line, size_t *o)
{
    if (*o + 1 < ZLOG_LINE_CAP - 1) line[(*o)++] = ' ';
}

/* Append a separating space and the sink's tag when one is configured, truncated to fit. */
static void zlog_append_tag(char *line, size_t *o, const zlog_sink *sink)
{
    if (sink->include_tag && sink->tag && sink->tag[0]) {
        size_t tl = strlen(sink->tag);
        zlog_append_space(line, o);
        if (tl > ZLOG_LINE_CAP - *o - 2) tl = ZLOG_LINE_CAP - *o - 2;
        memcpy(line + *o, sink->tag, tl);
        *o += tl;
    }
}

/* Append a separating space, then the message if present, then the newline and terminator. */
static void zlog_append_message(char *line, size_t *o, const char *message)
{
    zlog_append_space(line, o);
    if (message) {
        size_t ml = strlen(message);
        if (ml > ZLOG_LINE_CAP - *o - 2) ml = ZLOG_LINE_CAP - *o - 2;
        memcpy(line + *o, message, ml);
        *o += ml;
    }
    line[(*o)++] = '\n';
    line[*o] = '\0';
}

bool zlog_write(const zlog_sink *sink, zlog_level level, const char *message)
{
    if (!sink) return false;
    if (level < ZLOG_TRACE || level > ZLOG_ERROR) return false;
    if (level < sink->threshold || sink->threshold == ZLOG_OFF)
        return false;
    if (!sink->emit) return true; /* counted, dropped */

    char line[ZLOG_LINE_CAP];
    size_t o = 0;

    zlog_append_level_name(line, &o, level);
    zlog_append_tag(line, &o, sink);
    zlog_append_message(line, &o, message);

    sink->emit(sink->ctx, line);
    return true;
}

bool zlog_trace(const zlog_sink *sink, const char *msg)
{
    return zlog_write(sink, ZLOG_TRACE, msg);
}
bool zlog_debug(const zlog_sink *sink, const char *msg)
{
    return zlog_write(sink, ZLOG_DEBUG, msg);
}
bool zlog_info(const zlog_sink *sink, const char *msg)
{
    return zlog_write(sink, ZLOG_INFO, msg);
}
bool zlog_warn(const zlog_sink *sink, const char *msg)
{
    return zlog_write(sink, ZLOG_WARN, msg);
}
bool zlog_error(const zlog_sink *sink, const char *msg)
{
    return zlog_write(sink, ZLOG_ERROR, msg);
}
