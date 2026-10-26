/* zpq CLI: min-heap over integers from the command line.
 *
 *   zpq push <n> | pop | peek ...   ops applied left to right; pop and
 *                                   peek print the minimum
 */
#include "zpq/zpq.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static int cmp_long(const void *a, const void *b, void *ctx)
{
    (void)ctx;
    long va = *(const long *)a, vb = *(const long *)b;
    return (va > vb) - (va < vb);
}

static bool parse_long(const char *text, long *value)
{
    errno = 0;
    char *end;
    long parsed = strtol(text, &end, 10);
    if (end == text || *end || errno == ERANGE) return false;
    *value = parsed;
    return true;
}

struct cli_state {
    zpq *pq;
    long *storage;
    size_t nstored;
    bool output, write_failed;
};

static int apply_op(struct cli_state *state, int argc, char **argv, int *i)
{
    const char *op = argv[*i];
    if (strcmp(op, "push") == 0 && *i + 1 < argc) {
        long *slot = &state->storage[state->nstored];
        if (!parse_long(argv[++*i], slot)) {
            fprintf(stderr, "zpq: invalid integer\n");
            return 2;
        }
        if (!zpq_push(state->pq, slot)) {
            fprintf(stderr, "zpq: allocation failed\n");
            return 1;
        }
        state->nstored++;
    } else if (strcmp(op, "pop") == 0 || strcmp(op, "peek") == 0) {
        long *v = strcmp(op, "pop") == 0 ? zpq_pop(state->pq) : zpq_peek(state->pq);
        if (v) {
            state->output = true;
            if (printf("%ld\n", *v) < 0) state->write_failed = true;
        }
    } else if (strcmp(op, "len") == 0) {
        state->output = true;
        if (printf("%zu\n", zpq_len(state->pq)) < 0) state->write_failed = true;
    } else {
        fprintf(stderr, "zpq: unknown op %s\n", op);
        return 2;
    }
    return state->write_failed ? 1 : 0;
}

static int finish_output(const struct cli_state *state, int rc)
{
    if (state->output && (state->write_failed || fflush(stdout) != 0 || ferror(stdout))) {
        fprintf(stderr, "zpq: output write failed\n");
        return 1;
    }
    return rc;
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
    struct cli_state state = {.pq = pq, .storage = storage};

    int rc = 0;
    for (int i = 1; i < argc && rc == 0; i++)
        rc = apply_op(&state, argc, argv, &i);

    free(storage);
    zpq_destroy(pq);
    return finish_output(&state, rc);
}
