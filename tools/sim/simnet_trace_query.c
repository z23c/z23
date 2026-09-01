/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simnet_trace_query — linear-scan filter over a simnet full-state trace
 * (engine/modules/sim/include/sim/simnet_trace.h; docs/CHAOS_HARNESS.md "Recording a
 * full-state trace").
 *
 * A trace is one NDJSON object per (node, event) snapshot, written by
 * `zclassic23-chaos --trace-dir=PATH` (or the `trace_dir PATH` scenario
 * command). This tool answers "what did node N's state look like at event
 * E" without a database: read the file once, parse each line, print the
 * ones that match every filter given. No filters given prints every line.
 * Deliberately linear-scan-simple — traces are per-scenario-run artifacts,
 * not a growing production log.
 *
 * Standalone-build discipline (mirrors tools/postmortem_to_scenario.c):
 * a trace file is plain NDJSON once written, so this tool links ONLY
 * platform/modules/json (the trace's own format) plus the safe_alloc/log_level it
 * transitively needs — no DB, no node libs, no Tor, no simulator/consensus
 * code at all.
 */

#define _POSIX_C_SOURCE 200809L

#include "base/safe_alloc.h"
#include "json/json.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STQ_MAX_LINE (64u * 1024u)
#define STQ_EVENT_MAX 64u

struct stq_filter {
    bool have_node;
    int64_t node_id;
    bool have_event;
    char event[STQ_EVENT_MAX];
    bool have_seq;
    int64_t seq;
};

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s --file=PATH [--node=N] [--event=NAME] [--seq=N]\n"
            "  Filters an NDJSON simnet trace and prints matching lines.\n"
            "  No filter flags: prints every line. A match summary line\n"
            "  (matched/total) always goes to stderr.\n",
            argv0);
}

static bool stq_parse_i64(const char *s, int64_t *out)
{
    if (!s || !*s)
        return false;
    errno = 0;
    char *end = NULL;
    long long v = strtoll(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0')
        return false;
    *out = (int64_t)v;
    return true;
}

static bool stq_line_matches(const struct json_value *v,
                             const struct stq_filter *f)
{
    if (f->have_node) {
        const struct json_value *n = json_get(v, "node_id");
        if (!n || json_is_null(n) || json_get_int(n) != f->node_id)
            return false;
    }
    if (f->have_event) {
        const struct json_value *e = json_get(v, "event");
        const char *es = e ? json_get_str(e) : NULL;
        if (!es || strcmp(es, f->event) != 0)
            return false;
    }
    if (f->have_seq) {
        const struct json_value *s = json_get(v, "seq");
        if (!s || json_is_null(s) || json_get_int(s) != f->seq)
            return false;
    }
    return true;
}

int main(int argc, char **argv)
{
    const char *path = NULL;
    struct stq_filter filter;
    memset(&filter, 0, sizeof(filter));

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--file=", 7) == 0) {
            path = argv[i] + 7;
        } else if (strncmp(argv[i], "--node=", 7) == 0) {
            if (!stq_parse_i64(argv[i] + 7, &filter.node_id)) {
                usage(argv[0]);
                return 2;
            }
            filter.have_node = true;
        } else if (strncmp(argv[i], "--event=", 8) == 0) {
            if (strlen(argv[i] + 8) >= sizeof(filter.event)) {
                fprintf(stderr, "simnet_trace_query: --event value too long\n");
                return 2;
            }
            snprintf(filter.event, sizeof(filter.event), "%s", argv[i] + 8);
            filter.have_event = true;
        } else if (strncmp(argv[i], "--seq=", 6) == 0) {
            if (!stq_parse_i64(argv[i] + 6, &filter.seq)) {
                usage(argv[0]);
                return 2;
            }
            filter.have_seq = true;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    if (!path || !*path) {
        usage(argv[0]);
        return 2;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "simnet_trace_query: cannot open %s: %s\n", path,
                strerror(errno));
        return 1;
    }

    char *line = zcl_malloc(STQ_MAX_LINE, "simnet_trace_query.line_buf");
    if (!line) {
        fclose(fp);
        fprintf(stderr, "simnet_trace_query: out of memory\n");
        return 1;
    }

    size_t total = 0;
    size_t matched = 0;
    while (fgets(line, (int)STQ_MAX_LINE, fp)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (len == 0)
            continue;
        total++;

        struct json_value v;
        json_init(&v);
        if (!json_read(&v, line, len)) {
            fprintf(stderr,
                    "simnet_trace_query: skipping malformed line %zu\n",
                    total);
            json_free(&v);
            continue;
        }
        if (stq_line_matches(&v, &filter)) {
            matched++;
            printf("%s\n", line);
        }
        json_free(&v);
    }

    free(line);
    fclose(fp);
    fprintf(stderr, "simnet_trace_query: %zu/%zu lines matched\n", matched,
            total);
    return 0;
}
