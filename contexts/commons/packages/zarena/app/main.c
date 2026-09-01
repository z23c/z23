/* zarena demo: build a small parse-like structure in one arena. */
#include "zarena/zarena.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    static unsigned char buf[1024];
    zarena a;
    zarena_init(&a, buf, sizeof buf);

    const char *words[] = {"bump", "arena", "allocator"};
    for (size_t i = 0; i < 3; i++) {
        size_t n = strlen(words[i]) + 1;
        char *copy = zarena_alloc(&a, n, 1);
        if (!copy) {
            fprintf(stderr, "arena exhausted\n");
            return 1;
        }
        memcpy(copy, words[i], n);
        printf("%s ", copy);
    }
    printf("(%zu/%zu bytes used)\n", zarena_used(&a), sizeof buf);
    zarena_clear(&a);
    printf("after clear: %zu bytes used\n", zarena_used(&a));
    return 0;
}
