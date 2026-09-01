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

bool zlog_write(const zlog_sink *sink, zlog_level level, const char *message)
{
    if (!sink) return false;
    if (level < ZLOG_TRACE || level > ZLOG_ERROR) return false;
    if (level < sink->threshold || sink->threshold == ZLOG_OFF)
        return false;
    if (!sink->emit) return true; /* counted, dropped */

    char line[ZLOG_LINE_CAP];
    size_t o = 0;

    const char *name = zlog_level_name(level);
    size_t nl = strlen(name);
    if (nl > sizeof line - 2) nl = sizeof line - 2;
    memcpy(line + o, name, nl);
    o += nl;

    if (sink->include_tag && sink->tag && sink->tag[0]) {
        size_t tl = strlen(sink->tag);
        if (o + 1 < sizeof line - 1) line[o++] = ' ';
        if (tl > sizeof line - o - 2) tl = sizeof line - o - 2;
        memcpy(line + o, sink->tag, tl);
        o += tl;
    }

    if (o + 1 < sizeof line - 1) line[o++] = ' ';

    if (message) {
        size_t ml = strlen(message);
        if (ml > sizeof line - o - 2) ml = sizeof line - o - 2;
        memcpy(line + o, message, ml);
        o += ml;
    }
    line[o++] = '\n';
    line[o] = '\0';

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
