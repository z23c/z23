/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zslot CLI: prove stale handles miss.
 *
 *   zslot selftest
 *     insert 3, drop the middle, reuse the slot, print whether the
 *     old handle still resolves (it must not).
 *
 *   zslot CAP < ops
 *     CAP is slot count for 4-byte values (1..256).
 *     ops, one per line:
 *       i N     insert uint32 N; prints "i N -> ID" or FULL
 *       g ID    get; prints "g ID -> N" or MISS
 *       r ID    remove; prints "r ID -> ok" or rejected
 *       n       prints "n -> live K/CAP"
 *     IDs are printed as 16 lowercase hex digits.
 */
#include "zslot/zslot.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#define MAX_CAP 256u

static unsigned char store[8192];

struct output_state { bool attempted, failed; };

static void record_output(struct output_state *out, int result)
{
    out->attempted = true;
    if (result < 0) out->failed = true;
}

static int finish_output(const struct output_state *out, int result)
{
    if (out->attempted && (out->failed || fflush(stdout) != 0 || ferror(stdout))) {
        fprintf(stderr, "zslot: output write failed\n");
        return 1;
    }
    return result;
}

static bool parse_unsigned(const char *text, int base, unsigned long long limit,
                            unsigned long long *value, char **tail)
{
    const char *sign = text;
    while (isspace((unsigned char)*sign)) sign++;
    bool negative = *sign == '-';
    errno = 0;
    char *end;
    unsigned long long n = strtoull(text, &end, base);
    if (end == text || errno == ERANGE || n > limit || (negative && n != 0)) return false;
    *value = n;
    *tail = end;
    return true;
}

static int selftest(void)
{
    zslot t;
    if (!zslot_init(&t, store, sizeof(store), sizeof(uint32_t))) {
        fprintf(stderr, "zslot: init failed\n");
        return 1;
    }
    uint32_t a = 10, b = 20, c = 30, d = 40;
    zslot_id ia = zslot_insert(&t, &a);
    zslot_id ib = zslot_insert(&t, &b);
    zslot_id ic = zslot_insert(&t, &c);
    if (!ia || !ib || !ic) {
        fprintf(stderr, "zslot: insert failed\n");
        return 1;
    }
    if (!zslot_remove(&t, ib)) {
        fprintf(stderr, "zslot: remove failed\n");
        return 1;
    }
    zslot_id id = zslot_insert(&t, &d);
    if (!id) {
        fprintf(stderr, "zslot: reuse insert failed\n");
        return 1;
    }
    int stale_miss = zslot_get(&t, ib) == NULL;
    int reused = zslot_id_index(id) == zslot_id_index(ib) &&
                 zslot_id_generation(id) != zslot_id_generation(ib);
    int live_ok = zslot_get(&t, ia) && zslot_get(&t, ic) && zslot_get(&t, id) &&
                  *(uint32_t *)zslot_get(&t, id) == 40;
    if (!stale_miss || !reused || !live_ok) {
        fprintf(stderr, "zslot: invariant broken stale=%d reuse=%d live=%d\n",
                stale_miss, reused, live_ok);
        return 1;
    }
    struct output_state out = {0};
    record_output(&out, printf("ok: stale-miss live=%u reused-index=%u gen %u -> %u\n",
           zslot_live(&t), zslot_id_index(id), zslot_id_generation(ib),
           zslot_id_generation(id)));
    return finish_output(&out, 0);
}

static int insert_line(zslot *t, const char *line, struct output_state *out)
{
    char *end;
    unsigned long long value;
    if (!parse_unsigned(line + 1, 10, UINT32_MAX, &value, &end) ||
        (*end && *end != '\n')) {
        fprintf(stderr, "zslot: bad insert '%s'", line);
        return 2;
    }
    uint32_t n = (uint32_t)value;
    zslot_id id = zslot_insert(t, &n);
    if (!id) record_output(out, puts("i -> FULL"));
    else record_output(out, printf("i %llu -> %016llx\n", value, (unsigned long long)id));
    return out->failed ? 1 : 0;
}

static int id_line(zslot *t, const char *line, struct output_state *out)
{
    char *end;
    unsigned long long value;
    if (!parse_unsigned(line + 1, 16, UINT64_MAX, &value, &end) ||
        (*end && *end != '\n')) {
        fprintf(stderr, "zslot: bad id '%s'", line);
        return 2;
    }
    zslot_id id = (zslot_id)value;
    if (line[0] == 'g') {
        uint32_t *p = zslot_get(t, id);
        if (!p) record_output(out, printf("g %016llx -> MISS\n", value));
        else record_output(out, printf("g %016llx -> %u\n", value, *p));
    } else {
        record_output(out, printf("r %016llx -> %s\n", value,
                                 zslot_remove(t, id) ? "ok" : "rejected"));
    }
    return out->failed ? 1 : 0;
}

static int run_lines(zslot *t)
{
    char line[128];
    struct output_state out = {0};
    int result = 0;
    while (result == 0 && fgets(line, sizeof line, stdin)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (line[0] == 'i') result = insert_line(t, line, &out);
        else if (line[0] == 'g' || line[0] == 'r') result = id_line(t, line, &out);
        else if (line[0] == 'n') {
            record_output(&out, printf("n -> live %u/%u\n", zslot_live(t), zslot_cap(t)));
            if (out.failed) result = 1;
        } else {
            fprintf(stderr, "zslot: unknown op '%s'", line);
            result = 2;
        }
    }
    if (ferror(stdin)) {
        fprintf(stderr, "zslot: input read failed\n");
        result = 1;
    }
    return finish_output(&out, result);
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "selftest") == 0)
        return selftest();
    if (argc != 2) {
        fprintf(stderr, "usage: zslot selftest | zslot CAP < ops\n");
        return 2;
    }
    char *end = NULL;
    unsigned long long cap;
    if (!parse_unsigned(argv[1], 10, MAX_CAP, &cap, &end) || *end || cap < 1) {
        fprintf(stderr, "zslot: CAP must be 1..%u\n", MAX_CAP);
        return 2;
    }
    size_t need = zslot_storage_bytes((uint32_t)cap, sizeof(uint32_t));
    if (!need || need > sizeof(store)) {
        fprintf(stderr, "zslot: storage overflow\n");
        return 2;
    }
    zslot t;
    if (!zslot_init(&t, store, need, sizeof(uint32_t))) {
        fprintf(stderr, "zslot: init failed\n");
        return 2;
    }

    return run_lines(&t);
}
