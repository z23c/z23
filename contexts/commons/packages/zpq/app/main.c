/* zpq CLI: min-heap over integers from the command line.
 *
 *   zpq push <n> | pop | peek ...   ops applied left to right; pop and
 *                                   peek print the minimum
 */
#include "zpq/zpq.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cmp_long(const void *a, const void *b, void *ctx)
{
    (void)ctx;
    long va = *(const long *)a, vb = *(const long *)b;
    return (va > vb) - (va < vb);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: zpq <push N|pop|peek|len>...\n");
        return 2;
    }

    zpq *pq = zpq_create(cmp_long, NULL, (zpq_alloc){0});
    if (!pq) { fprintf(stderr, "zpq: out of memory\n"); return 1; }

    long *storage = malloc((size_t)argc * sizeof(long));
    if (!storage) { zpq_destroy(pq); return 1; }
    size_t nstored = 0;

    int rc = 0;
    for (int i = 1; i < argc && rc == 0; i++) {
        if (strcmp(argv[i], "push") == 0 && i + 1 < argc) {
            storage[nstored] = strtol(argv[++i], NULL, 10);
            if (!zpq_push(pq, &storage[nstored])) {
                fprintf(stderr, "zpq: allocation failed\n");
                rc = 1;
            }
            nstored++;
        } else if (strcmp(argv[i], "pop") == 0) {
            long *v = zpq_pop(pq);
            if (v) printf("%ld\n", *v);
        } else if (strcmp(argv[i], "peek") == 0) {
            long *v = zpq_peek(pq);
            if (v) printf("%ld\n", *v);
        } else if (strcmp(argv[i], "len") == 0) {
            printf("%zu\n", zpq_len(pq));
        } else {
            fprintf(stderr, "zpq: unknown op %s\n", argv[i]);
            rc = 2;
        }
    }

    free(storage);
    zpq_destroy(pq);
    return rc;
}
