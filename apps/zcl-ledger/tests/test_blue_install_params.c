/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_install_params.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

int main(void) {
    uint8_t output[ZCL_BLUE_INSTALL_PARAMS_MAX];
    static const uint8_t expected[] = {
        0x01, 13, 'Z','C','L',' ','S','i','g','n',' ','T','e','s','t',
        0x02, 5, '0','.','1','.','0',
        0x04, 22, 0x01, 5,
        0x80, 0, 0, 0x2c,
        0x80, 0, 0, 0x93,
        0x80, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0
    };
    size_t length = blue_install_params("ZCL Sign Test", "0.1.0", true,
                                        output);
    assert(length == sizeof expected && memcmp(output, expected, length) == 0);
    static const uint8_t review[] = {
        0x01, 10, 'Z','C','L',' ','R','e','v','i','e','w',
        0x02, 5, '0','.','2','.','0', 0x04, 1, 0
    };
    length = blue_install_params("ZCL Review", "0.2.0", false, output);
    assert(length == sizeof review && memcmp(output, review, length) == 0);
    assert(blue_install_params("", "0.1.0", true, output) == 0);
    assert(blue_install_params("ZCL", "0.1", true, output) == 0);
    assert(blue_install_params(NULL, "0.1.0", true, output) == 0);
    return 0;
}
