/* zlog CLI: emit log lines to stderr.
 *
 *   zlog [-t tag] [-l level] <level> <message>...
 *   level: trace|debug|info|warn|error (default threshold info)
 */
#include "zlog/zlog.h"

#include <stdio.h>
#include <string.h>

static void stderr_emit(void *ctx, const char *line)
{
    (void)ctx;
    fputs(line, stderr);
}

int main(int argc, char **argv)
{
    const char *tag = NULL;
    const char *threshold = "info";
    int i = 1;
    while (i + 1 < argc && argv[i][0] == '-') {
        if (strcmp(argv[i], "-t") == 0) { tag = argv[i + 1]; i += 2; }
        else if (strcmp(argv[i], "-l") == 0) { threshold = argv[i + 1]; i += 2; }
        else break;
    }
    if (i + 1 >= argc) {
        fprintf(stderr,
            "usage: zlog [-t tag] [-l level] <level> <message>\n");
        return 2;
    }

    zlog_level level = zlog_level_parse(argv[i]);
    if (level == ZLOG_OFF && strcmp(argv[i], "off") != 0
        && strcmp(argv[i], "OFF") != 0) {
        fprintf(stderr, "zlog: unknown level %s\n", argv[i]);
        return 2;
    }

    zlog_sink sink = { stderr_emit, NULL, zlog_level_parse(threshold),
                       true, tag };
    zlog_write(&sink, level, argv[i + 1]);
    return 0;
}
