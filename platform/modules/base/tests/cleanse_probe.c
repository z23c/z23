#include "base/cleanse.h"

#include <stddef.h>
#include <stdint.h>

void package_base_cleanse_probe(uint8_t *buf, size_t len)
{
    memory_cleanse(buf, len);
}
