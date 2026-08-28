/* Headless smoke acceptance for the native system CSPRNG. */
#include "platform/rng.h"

#include <stdio.h>
#include <string.h>

static bool any_nonzero(const uint8_t *bytes, size_t size)
{
    uint8_t combined = 0;
    for (size_t i = 0; i < size; i++)
        combined |= bytes[i];
    return combined != 0;
}

int main(void)
{
    uint8_t first[64] = {0};
    uint8_t second[64] = {0};
    if (!rng_fill(first, sizeof(first)) ||
        !rng_fill(second, sizeof(second)))
        return 1;
    if (!any_nonzero(first, sizeof(first)) ||
        !any_nonzero(second, sizeof(second)))
        return 2;
    if (memcmp(first, second, sizeof(first)) == 0)
        return 3;
    if (!rng_fill(NULL, 0) || rng_fill(NULL, 1))
        return 4;
    puts("rng_acceptance: PASS");
    return 0;
}
