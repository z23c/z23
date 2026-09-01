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
        if (strncmp(op, "push:", 5) == 0) {
            if (!zvec_push(v, (void *)(op + 5))) { zvec_destroy(v); return 1; }
        } else if (strcmp(op, "pop") == 0) {
            zvec_pop(v);
        } else if (strncmp(op, "insert:", 7) == 0) {
            const char *colon = strchr(op + 7, ':');
            if (!colon) { zvec_destroy(v); return 2; }
            size_t idx = (size_t)strtoull(op + 7, NULL, 10);
            if (!zvec_insert(v, idx, (void *)(colon + 1))) {
                fprintf(stderr, "zvec: insert failed\n");
                zvec_destroy(v);
                return 1;
            }
        } else if (strncmp(op, "remove:", 7) == 0) {
            zvec_remove(v, (size_t)strtoull(op + 7, NULL, 10));
        } else if (strncmp(op, "swap-remove:", 12) == 0) {
            zvec_swap_remove(v, (size_t)strtoull(op + 12, NULL, 10));
        } else if (strcmp(op, "clear") == 0) {
            zvec_clear(v);
        } else {
            zvec_destroy(v);
            return 2;
        }
    }

    for (size_t i = 0; i < zvec_len(v); i++)
        puts((const char *)zvec_get(v, i));
    zvec_destroy(v);
    return 0;
}
