/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * jsonq — path query over a JSON document on stdin.
 *
 * Python is banned in this repository. Shell scripts extract JSON with
 * grep/sed when the document is flat; nested RPC and native-command
 * envelopes need a real parser. This is that parser, built on the in-tree
 * zjsonp pull parser (allocation-free, depth-bounded). No jq, no Python.
 *
 *   printf '%s' "$json" | jsonq get data.plan_id
 *   printf '%s' "$json" | jsonq has result.ok
 *   printf '%s' "$json" | jsonq eq ok true
 *   printf '%s' "$json" | jsonq count result
 *   printf '%s' "$json" | jsonq raw data
 *   printf '%s' "$json" | jsonq type state.tracked
 *   printf '%s' "$json" | jsonq keys data
 *   printf '%s' "$json" | jsonq unwrap
 *
 * PATH: dotted keys and [index] from the document root. Leading '.' is
 * optional. Example: result.items[1].id
 *
 * get/raw print the value and exit 0. Missing path exits 1. Malformed
 * JSON or usage exits 2. unwrap prints result when the envelope is a
 * JSON-RPC object with a null/absent error; a present error exits 2.
 */
#include "zjsonp/zjsonp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    MAX_INPUT = 16 << 20,
    MAX_SEGS = 32,
    MAX_KEY = 256,
    DECODE_CAP = 1 << 16
};

typedef enum { SEG_KEY = 0, SEG_INDEX = 1 } seg_kind;

typedef struct {
    seg_kind kind;
    char key[MAX_KEY];
    size_t key_len;
    int index;
} path_seg;

typedef struct {
    bool is_array;
    int index;
    char key[MAX_KEY];
    size_t key_len;
    bool have_key;
} frame;

typedef enum {
    CMD_GET = 0,
    CMD_RAW,
    CMD_TYPE,
    CMD_HAS,
    CMD_EQ,
    CMD_COUNT,
    CMD_KEYS,
    CMD_UNWRAP
} cmd_kind;

static char g_input[MAX_INPUT];
static char g_decode[DECODE_CAP];
static path_seg g_segs[MAX_SEGS];
static int g_nsegs;
static frame g_stack[ZJRP_MAX_DEPTH];
static int g_depth;

static void usage(void)
{
    fputs("usage: jsonq get|raw|type|has|eq|count|keys PATH\n"
          "       jsonq unwrap\n"
          "Read one JSON document from stdin.\n",
          stderr);
}

static int parse_path(const char *path)
{
    const char *p = path;
    g_nsegs = 0;
    if (!p || !*p || (p[0] == '.' && p[1] == '\0'))
        return 0;
    if (*p == '.')
        p++;
    while (*p) {
        if (g_nsegs >= MAX_SEGS) {
            fputs("jsonq: path too deep\n", stderr);
            return -1;
        }
        path_seg *s = &g_segs[g_nsegs];
        if (*p == '[') {
            p++;
            if (*p < '0' || *p > '9') {
                fputs("jsonq: expected array index\n", stderr);
                return -1;
            }
            int idx = 0;
            while (*p >= '0' && *p <= '9') {
                idx = idx * 10 + (*p - '0');
                p++;
            }
            if (*p != ']') {
                fputs("jsonq: missing ]\n", stderr);
                return -1;
            }
            p++;
            s->kind = SEG_INDEX;
            s->index = idx;
            s->key_len = 0;
            g_nsegs++;
            if (*p == '.')
                p++;
            continue;
        }
        const char *start = p;
        while (*p && *p != '.' && *p != '[')
            p++;
        size_t n = (size_t)(p - start);
        if (n == 0 || n >= MAX_KEY) {
            fputs("jsonq: empty or oversized path segment\n", stderr);
            return -1;
        }
        s->kind = SEG_KEY;
        memcpy(s->key, start, n);
        s->key[n] = '\0';
        s->key_len = n;
        s->index = 0;
        g_nsegs++;
        if (*p == '.')
            p++;
    }
    return 0;
}

static bool decode_key(const char *text, const zjsonp_event *ev,
                       char *out, size_t cap, size_t *len_out)
{
    size_t n = zjsonp_str_decode(text, ev, out, cap);
    if (n == SIZE_MAX || n >= cap)
        return false;
    out[n] = '\0';
    *len_out = n;
    return true;
}

static bool selector_eq(const frame *fr, const path_seg *want)
{
    if (fr->is_array) {
        if (want->kind != SEG_INDEX)
            return false;
        return fr->index == want->index;
    }
    if (want->kind != SEG_KEY)
        return false;
    if (!fr->have_key)
        return false;
    return fr->key_len == want->key_len &&
           memcmp(fr->key, want->key, fr->key_len) == 0;
}

static int skip_container(zjsonp *p, unsigned open_depth)
{
    for (;;) {
        zjsonp_event ev;
        zjsonp_status st = zjsonp_next(p, &ev);
        if (st != ZJRP_OK)
            return -1;
        if ((ev.kind == ZJRP_OBJ_CLOSE || ev.kind == ZJRP_ARR_CLOSE) &&
            p->depth < open_depth)
            return 0;
    }
}

static const char *kind_type(zjsonp_event_kind k)
{
    switch (k) {
    case ZJRP_OBJ_OPEN:
        return "object";
    case ZJRP_ARR_OPEN:
        return "array";
    case ZJRP_STR:
        return "string";
    case ZJRP_NUM:
        return "number";
    case ZJRP_BOOL:
        return "bool";
    case ZJRP_NULL:
        return "null";
    default:
        return "?";
    }
}

static int emit_scalar(const char *text, const zjsonp_event *ev, bool raw)
{
    if (ev->kind == ZJRP_STR) {
        if (raw) {
            if (ev->off == 0)
                return -1;
            fwrite(text + ev->off - 1, 1, ev->len + 2, stdout);
            fputc('\n', stdout);
            return 0;
        }
        size_t n = zjsonp_str_decode(text, ev, g_decode, sizeof g_decode);
        if (n == SIZE_MAX || n >= sizeof g_decode)
            return -1;
        fwrite(g_decode, 1, n, stdout);
        fputc('\n', stdout);
        return 0;
    }
    fwrite(text + ev->off, 1, ev->len, stdout);
    fputc('\n', stdout);
    return 0;
}

static int emit_raw_range(const char *text, size_t start, size_t end)
{
    if (end < start || end > MAX_INPUT)
        return -1;
    fwrite(text + start, 1, end - start, stdout);
    fputc('\n', stdout);
    return 0;
}

static int finish_matched_container(zjsonp *p, const char *text,
                                    const zjsonp_event *open, cmd_kind cmd,
                                    const char *eq)
{
    unsigned open_depth = p->depth;
    size_t start = open->off;
    const char *typ = kind_type(open->kind);
    if (cmd == CMD_HAS)
        return 0;
    if (cmd == CMD_TYPE) {
        puts(typ);
        return 0;
    }
    if (cmd == CMD_EQ)
        return 1;
    if (cmd == CMD_GET || cmd == CMD_RAW) {
        if (skip_container(p, open_depth) != 0)
            return 2;
        return emit_raw_range(text, start, p->pos);
    }
    if (cmd == CMD_COUNT) {
        int n = 0;
        if (open->kind == ZJRP_ARR_OPEN) {
            for (;;) {
                zjsonp_event ev;
                zjsonp_status st = zjsonp_next(p, &ev);
                if (st != ZJRP_OK)
                    return 2;
                if ((ev.kind == ZJRP_OBJ_CLOSE || ev.kind == ZJRP_ARR_CLOSE) &&
                    p->depth < open_depth) {
                    printf("%d\n", n);
                    return 0;
                }
                if (ev.kind == ZJRP_OBJ_OPEN || ev.kind == ZJRP_ARR_OPEN) {
                    n++;
                    if (skip_container(p, p->depth) != 0)
                        return 2;
                } else if (ev.kind == ZJRP_STR || ev.kind == ZJRP_NUM ||
                           ev.kind == ZJRP_BOOL || ev.kind == ZJRP_NULL) {
                    n++;
                }
            }
        }
        if (open->kind == ZJRP_OBJ_OPEN) {
            for (;;) {
                zjsonp_event ev;
                zjsonp_status st = zjsonp_next(p, &ev);
                if (st != ZJRP_OK)
                    return 2;
                if ((ev.kind == ZJRP_OBJ_CLOSE || ev.kind == ZJRP_ARR_CLOSE) &&
                    p->depth < open_depth) {
                    printf("%d\n", n);
                    return 0;
                }
                if (ev.kind == ZJRP_KEY)
                    n++;
            }
        }
        return 2;
    }
    if (cmd == CMD_KEYS) {
        if (open->kind != ZJRP_OBJ_OPEN)
            return 1;
        for (;;) {
            zjsonp_event ev;
            zjsonp_status st = zjsonp_next(p, &ev);
            if (st != ZJRP_OK)
                return 2;
            if ((ev.kind == ZJRP_OBJ_CLOSE || ev.kind == ZJRP_ARR_CLOSE) &&
                p->depth < open_depth)
                return 0;
            if (ev.kind == ZJRP_KEY) {
                size_t kn = 0;
                if (!decode_key(text, &ev, g_decode, sizeof g_decode, &kn))
                    return 2;
                fwrite(g_decode, 1, kn, stdout);
                fputc('\n', stdout);
            }
        }
    }
    (void)eq;
    return 2;
}

static int handle_matched_scalar(const char *text, const zjsonp_event *ev,
                                 cmd_kind cmd, const char *eq)
{
    if (cmd == CMD_HAS)
        return 0;
    if (cmd == CMD_TYPE) {
        puts(kind_type(ev->kind));
        return 0;
    }
    if (cmd == CMD_COUNT || cmd == CMD_KEYS)
        return 1;
    if (cmd == CMD_GET)
        return emit_scalar(text, ev, false);
    if (cmd == CMD_RAW)
        return emit_scalar(text, ev, true);
    if (cmd == CMD_EQ) {
        if (ev->kind == ZJRP_STR) {
            size_t n = zjsonp_str_decode(text, ev, g_decode, sizeof g_decode);
            if (n == SIZE_MAX || n >= sizeof g_decode)
                return 2;
            g_decode[n] = '\0';
            return strcmp(g_decode, eq) == 0 ? 0 : 1;
        }
        if (ev->len >= DECODE_CAP)
            return 2;
        memcpy(g_decode, text + ev->off, ev->len);
        g_decode[ev->len] = '\0';
        return strcmp(g_decode, eq) == 0 ? 0 : 1;
    }
    return 2;
}

static bool value_is_prefix_or_exact(int matched, bool *exact)
{
    if (matched == g_nsegs) {
        *exact = true;
        return true;
    }
    if (matched < g_nsegs) {
        *exact = false;
        return true;
    }
    return false;
}

static int child_match_rank(const frame *parent, int matched, bool *exact)
{
    if (matched >= g_nsegs)
        return -1;
    if (!selector_eq(parent, &g_segs[matched]))
        return 0;
    return value_is_prefix_or_exact(matched + 1, exact) ? 1 : 0;
}

static void bump_array(void)
{
    if (g_depth <= 0)
        return;
    frame *fr = &g_stack[g_depth - 1];
    if (fr->is_array)
        fr->index++;
    else
        fr->have_key = false;
}

static int walk(const char *text, size_t len, cmd_kind cmd, const char *eq)
{
    zjsonp p;
    zjsonp_init(&p, text, len);
    g_depth = 0;
    int matched = 0;
    bool first = true;

    for (;;) {
        zjsonp_event ev;
        zjsonp_status st = zjsonp_next(&p, &ev);
        if (st == ZJRP_DONE)
            return cmd == CMD_HAS ? 1 : 1;
        if (st != ZJRP_OK) {
            fprintf(stderr, "jsonq: %s at byte %zu\n",
                    zjsonp_status_name(st), zjsonp_pos(&p));
            return 2;
        }
        if (ev.kind == ZJRP_KEY) {
            if (g_depth <= 0)
                return 2;
            frame *fr = &g_stack[g_depth - 1];
            if (!decode_key(text, &ev, fr->key, sizeof fr->key, &fr->key_len))
                return 2;
            fr->have_key = true;
            continue;
        }
        if (ev.kind == ZJRP_OBJ_CLOSE || ev.kind == ZJRP_ARR_CLOSE) {
            if (g_depth <= 0)
                return 2;
            g_depth--;
            matched = g_depth > 0 ? g_depth - 1 : 0;
            bump_array();
            continue;
        }

        bool exact = false;
        bool is_open = ev.kind == ZJRP_OBJ_OPEN || ev.kind == ZJRP_ARR_OPEN;
        bool at_root = first;
        int rank;
        if (first) {
            first = false;
            if (g_nsegs == 0) {
                exact = true;
                rank = 1;
            } else if (is_open) {
                exact = false;
                rank = 1;
            } else {
                rank = 0;
            }
        } else if (g_depth <= 0) {
            return 2;
        } else {
            rank = child_match_rank(&g_stack[g_depth - 1], matched, &exact);
        }

        if (rank <= 0) {
            if (is_open) {
                if (skip_container(&p, p.depth) != 0)
                    return 2;
            }
            bump_array();
            continue;
        }
        if (exact) {
            if (is_open)
                return finish_matched_container(&p, text, &ev, cmd, eq);
            return handle_matched_scalar(text, &ev, cmd, eq);
        }
        if (!is_open) {
            bump_array();
            continue;
        }
        if (g_depth >= ZJRP_MAX_DEPTH)
            return 2;
        frame *fr = &g_stack[g_depth];
        memset(fr, 0, sizeof *fr);
        fr->is_array = ev.kind == ZJRP_ARR_OPEN;
        g_depth++;
        if (!at_root)
            matched++;
    }
}

static bool valid_document(const char *text, size_t len)
{
    zjsonp parser;
    zjsonp_event event;
    zjsonp_init(&parser, text, len);
    for (;;) {
        zjsonp_status status = zjsonp_next(&parser, &event);
        if (status == ZJRP_DONE)
            return true;
        if (status != ZJRP_OK)
            return false;
    }
}

static int cmd_unwrap(const char *text, size_t len)
{
    if (parse_path("error") != 0)
        return 2;
    int has_err = walk(text, len, CMD_HAS, NULL);
    if (has_err == 2)
        return 2;
    if (has_err == 0) {
        if (parse_path("error") != 0)
            return 2;
        if (walk(text, len, CMD_EQ, "null") != 0) {
            fputs("jsonq: json-rpc error\n", stderr);
            return 2;
        }
    }
    if (parse_path("result") != 0)
        return 2;
    if (walk(text, len, CMD_HAS, NULL) == 0) {
        if (parse_path("result") != 0)
            return 2;
        return walk(text, len, CMD_GET, NULL);
    }
    if (parse_path("") != 0)
        return 2;
    return walk(text, len, CMD_RAW, NULL);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage();
        return 2;
    }
    cmd_kind cmd;
    const char *path = NULL;
    const char *eq = NULL;
    if (strcmp(argv[1], "unwrap") == 0) {
        if (argc != 2) {
            usage();
            return 2;
        }
        cmd = CMD_UNWRAP;
    } else if (strcmp(argv[1], "get") == 0 || strcmp(argv[1], "raw") == 0 ||
               strcmp(argv[1], "type") == 0 || strcmp(argv[1], "has") == 0 ||
               strcmp(argv[1], "count") == 0 || strcmp(argv[1], "keys") == 0) {
        if (argc != 3) {
            usage();
            return 2;
        }
        path = argv[2];
        if (argv[1][0] == 'g')
            cmd = CMD_GET;
        else if (argv[1][0] == 'r')
            cmd = CMD_RAW;
        else if (argv[1][0] == 't')
            cmd = CMD_TYPE;
        else if (argv[1][0] == 'h')
            cmd = CMD_HAS;
        else if (argv[1][0] == 'c')
            cmd = CMD_COUNT;
        else
            cmd = CMD_KEYS;
    } else if (strcmp(argv[1], "eq") == 0) {
        if (argc != 4) {
            usage();
            return 2;
        }
        cmd = CMD_EQ;
        path = argv[2];
        eq = argv[3];
    } else {
        usage();
        return 2;
    }

    size_t len = fread(g_input, 1, sizeof g_input, stdin);
    if (ferror(stdin) || !feof(stdin)) {
        fprintf(stderr, "jsonq: read error or input over %d bytes\n",
                MAX_INPUT);
        return 2;
    }
    if (!valid_document(g_input, len)) {
        fputs("jsonq: input is not exactly one JSON document\n", stderr);
        return 2;
    }
    if (cmd == CMD_UNWRAP)
        return cmd_unwrap(g_input, len);
    if (parse_path(path) != 0)
        return 2;
    return walk(g_input, len, cmd, eq);
}
