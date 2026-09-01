/* Separate translation unit on purpose: the caller must observe the cleanse
 * after optimization and cannot see through the implementation body. */
#include "base/cleanse.h"

#include <stddef.h>
#include <stdint.h>

void base_foundation_cleanse_probe(uint8_t *buf, size_t len)
{
    memory_cleanse(buf, len);
}
