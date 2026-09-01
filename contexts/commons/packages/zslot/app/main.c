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

#define MAX_CAP 256u

static unsigned char store[8192];

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
    printf("ok: stale-miss live=%u reused-index=%u gen %u -> %u\n",
           zslot_live(&t), zslot_id_index(id), zslot_id_generation(ib),
           zslot_id_generation(id));
    return 0;
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
    unsigned long cap = strtoul(argv[1], &end, 10);
    if (!end || *end || cap < 1 || cap > MAX_CAP) {
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

    char line[128];
    int bad = 0;
    while (fgets(line, sizeof(line), stdin)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;
        if (line[0] == 'i') {
            unsigned long v = strtoul(line + 1, &end, 10);
            if (!end || (*end && *end != '\n')) {
                fprintf(stderr, "zslot: bad insert '%s'", line);
                bad = 2;
                break;
            }
            uint32_t n = (uint32_t)v;
            zslot_id id = zslot_insert(&t, &n);
            if (!id)
                puts("i -> FULL");
            else
                printf("i %lu -> %016llx\n", v, (unsigned long long)id);
        } else if (line[0] == 'g' || line[0] == 'r') {
            unsigned long long idv = strtoull(line + 1, &end, 16);
            if (!end || (*end && *end != '\n')) {
                fprintf(stderr, "zslot: bad id '%s'", line);
                bad = 2;
                break;
            }
            zslot_id id = (zslot_id)idv;
            if (line[0] == 'g') {
                uint32_t *p = zslot_get(&t, id);
                if (!p)
                    printf("g %016llx -> MISS\n", idv);
                else
                    printf("g %016llx -> %u\n", idv, *p);
            } else {
                printf("r %016llx -> %s\n", idv,
                       zslot_remove(&t, id) ? "ok" : "rejected");
            }
        } else if (line[0] == 'n') {
            printf("n -> live %u/%u\n", zslot_live(&t), zslot_cap(&t));
        } else {
            fprintf(stderr, "zslot: unknown op '%s'", line);
            bad = 2;
            break;
        }
    }
    return bad;
}
