/* zvec CLI: stack of strings, exercised from the command line.
 *
 *   zvec <op> <item>...    ops applied left to right, then the final
 *                          vector is printed one element per line
 * Ops: push:<s> pop insert:<i>:<s> remove:<i> swap-remove:<i> clear
 */
#include "zvec/zvec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>

static bool parse_index(const char *text, char terminator, size_t *index,
                         const char **tail)
{
    const char *sign = text;
    while (isspace((unsigned char)*sign)) sign++;
    bool negative = *sign == '-';
    errno = 0;
    char *end;
    unsigned long long value = strtoull(text, &end, 10);
    if (end == text || *end != terminator || errno == ERANGE ||
        value > SIZE_MAX || (negative && value != 0)) return false;
    *index = (size_t)value;
    if (tail) *tail = end;
    return true;
}

/* -1 means this is not an indexed operation; otherwise return its CLI
 * status. The caller owns vector cleanup for every failure. */
static int apply_indexed(zvec *v, const char *op)
{
    size_t index;
    if (strncmp(op, "insert:", 7) == 0) {
        const char *colon;
        if (!parse_index(op + 7, ':', &index, &colon)) goto bad_index;
        if (!zvec_insert(v, index, (void *)(colon + 1))) {
            fprintf(stderr, "zvec: insert failed\n");
            return 1;
        }
    } else if (strncmp(op, "remove:", 7) == 0) {
        if (!parse_index(op + 7, '\0', &index, NULL)) goto bad_index;
        zvec_remove(v, index);
    } else if (strncmp(op, "swap-remove:", 12) == 0) {
        if (!parse_index(op + 12, '\0', &index, NULL)) goto bad_index;
        zvec_swap_remove(v, index);
    } else return -1;
    return 0;
bad_index:
    fprintf(stderr, "zvec: invalid index\n");
    return 2;
}

static bool print_vector(const zvec *v)
{
    size_t count = zvec_len(v);
    for (size_t i = 0; i < count; i++) {
        if (puts((const char *)zvec_get(v, i)) < 0) return false;
    }
    return !count || (fflush(stdout) == 0 && !ferror(stdout));
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "usage: zvec <push:s|pop|insert:i:s|remove:i|swap-remove:i|clear>...\n");
        return 2;
    }

    zvec *v = zvec_create((zvec_alloc){0});
    if (!v) { fprintf(stderr, "zvec: out of memory\n"); return 1; }

    for (int i = 1; i < argc; i++) {
        const char *op = argv[i];
        int indexed = apply_indexed(v, op);
        if (indexed >= 0) {
            if (indexed != 0) { zvec_destroy(v); return indexed; }
            continue;
        }
        if (strncmp(op, "push:", 5) == 0) {
            if (!zvec_push(v, (void *)(op + 5))) { zvec_destroy(v); return 1; }
        } else if (strcmp(op, "pop") == 0) {
            zvec_pop(v);
        } else if (strcmp(op, "clear") == 0) {
            zvec_clear(v);
        } else {
            zvec_destroy(v);
            return 2;
        }
    }

    bool printed = print_vector(v);
    zvec_destroy(v);
    if (!printed) {
        fprintf(stderr, "zvec: output write failed\n");
        return 1;
    }
    return 0;
}
