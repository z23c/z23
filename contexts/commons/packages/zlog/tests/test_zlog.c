#include "zlog/zlog.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

struct capture {
    char lines[16][300];
    size_t count;
};

static void capture_emit(void *ctx, const char *line)
{
    struct capture *c = ctx;
    if (c->count >= 16) return;
    size_t n = strlen(line);
    if (n >= sizeof c->lines[0]) n = sizeof c->lines[0] - 1;
    memcpy(c->lines[c->count], line, n);
    c->lines[c->count][n] = '\0';
    c->count++;
}

static void test_levels_and_threshold(void)
{
    struct capture cap = {0};
    zlog_sink s = { capture_emit, &cap, ZLOG_INFO, true, "net" };

    CHECK(!zlog_trace(&s, "too low"));
    CHECK(!zlog_debug(&s, "too low"));
    CHECK(zlog_info(&s, "hello"));
    CHECK(zlog_warn(&s, "careful"));
    CHECK(zlog_error(&s, "bad"));
    CHECK(cap.count == 3);
    CHECK(strcmp(cap.lines[0], "INFO net hello\n") == 0);
    CHECK(strcmp(cap.lines[1], "WARN net careful\n") == 0);
    CHECK(strcmp(cap.lines[2], "ERROR net bad\n") == 0);

    /* OFF silences everything. */
    s.threshold = ZLOG_OFF;
    CHECK(!zlog_error(&s, "silence"));
    CHECK(cap.count == 3);

    /* TRACE threshold lets all through. */
    s.threshold = ZLOG_TRACE;
    CHECK(zlog_trace(&s, "fine"));
    CHECK(strcmp(cap.lines[3], "TRACE net fine\n") == 0);

    /* Invalid level values rejected. */
    CHECK(!zlog_write(&s, (zlog_level)-1, "x"));
    CHECK(!zlog_write(&s, (zlog_level)5, "x"));

    /* NULL sink / NULL message. */
    CHECK(!zlog_write(NULL, ZLOG_INFO, "x"));
    CHECK(zlog_write(&s, ZLOG_INFO, NULL)); /* emits header-only line */

    /* NULL emit callback: counted, nothing written. */
    zlog_sink silent = { NULL, NULL, ZLOG_TRACE, true, "t" };
    CHECK(zlog_write(&silent, ZLOG_INFO, "gone"));
}

static void test_no_tag(void)
{
    struct capture cap = {0};
    zlog_sink s = { capture_emit, &cap, ZLOG_TRACE, false, "ignored" };
    CHECK(zlog_info(&s, "plain"));
    CHECK(strcmp(cap.lines[0], "INFO plain\n") == 0);

    /* include_tag with NULL tag behaves like no tag. */
    s.include_tag = true;
    s.tag = NULL;
    CHECK(zlog_info(&s, "plain2"));
    CHECK(strcmp(cap.lines[1], "INFO plain2\n") == 0);

    s.tag = "";
    CHECK(zlog_info(&s, "plain3"));
    CHECK(strcmp(cap.lines[2], "INFO plain3\n") == 0);
}

static void test_truncation(void)
{
    struct capture cap = {0};
    zlog_sink s = { capture_emit, &cap, ZLOG_TRACE, true, "sys" };

    char huge[1000];
    memset(huge, 'x', sizeof huge - 1);
    huge[sizeof huge - 1] = '\0';

    CHECK(zlog_info(&s, huge));
    CHECK(cap.count == 1);
    size_t n = strlen(cap.lines[0]);
    CHECK(n < 256);            /* line cap respected */
    CHECK(cap.lines[0][n - 1] == '\n');
    CHECK(strncmp(cap.lines[0], "INFO sys ", 9) == 0);

    /* Very long tag also bounded. */
    char bigtag[600];
    memset(bigtag, 't', sizeof bigtag - 1);
    bigtag[sizeof bigtag - 1] = '\0';
    s.tag = bigtag;
    CHECK(zlog_warn(&s, "msg"));
    CHECK(strlen(cap.lines[1]) < 256);
}

static void test_names_and_parse(void)
{
    CHECK(strcmp(zlog_level_name(ZLOG_TRACE), "TRACE") == 0);
    CHECK(strcmp(zlog_level_name(ZLOG_DEBUG), "DEBUG") == 0);
    CHECK(strcmp(zlog_level_name(ZLOG_INFO), "INFO") == 0);
    CHECK(strcmp(zlog_level_name(ZLOG_WARN), "WARN") == 0);
    CHECK(strcmp(zlog_level_name(ZLOG_ERROR), "ERROR") == 0);
    CHECK(strcmp(zlog_level_name(ZLOG_OFF), "OFF") == 0);
    CHECK(strcmp(zlog_level_name((zlog_level)99), "OFF") == 0);

    CHECK(zlog_level_parse("trace") == ZLOG_TRACE);
    CHECK(zlog_level_parse("DEBUG") == ZLOG_DEBUG);
    CHECK(zlog_level_parse("Info") == ZLOG_INFO);
    CHECK(zlog_level_parse("warn") == ZLOG_WARN);
    CHECK(zlog_level_parse("ERROR") == ZLOG_ERROR);
    CHECK(zlog_level_parse("off") == ZLOG_OFF);
    CHECK(zlog_level_parse("nonsense") == ZLOG_OFF);
    CHECK(zlog_level_parse(NULL) == ZLOG_OFF);
    /* Prefixes must not match. */
    CHECK(zlog_level_parse("information") == ZLOG_OFF);
    CHECK(zlog_level_parse("warnx") == ZLOG_OFF);
}

int main(void)
{
    test_levels_and_threshold();
    test_no_tag();
    test_truncation();
    test_names_and_parse();
    puts("test_zlog: all groups passed (levels notag trunc names)");
    return 0;
}
