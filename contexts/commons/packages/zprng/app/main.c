/* zprng demo: print n uniform random numbers from a seed. */
#include "zprng/zprng.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    uint64_t seed = argc > 1 ? strtoull(argv[1], NULL, 10) : 42;
    unsigned long count = argc > 2 ? strtoul(argv[2], NULL, 10) : 5;
    zxoshiro256ss rng;

    zxoshiro256ss_init(&rng, seed);
    for (unsigned long i = 0; i < count; i++)
        printf("%llu\n", (unsigned long long)zxoshiro256ss_next(&rng));
    return 0;
}
