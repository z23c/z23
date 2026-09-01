#include "base/checked.h"

#include <stddef.h>

int main(void)
{
    size_t bytes;
    return zcl_size_mul(128, sizeof(uint64_t), &bytes) && bytes == 1024 ? 0 : 1;
}
