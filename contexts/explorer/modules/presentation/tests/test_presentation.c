#include "presentation/zclassic_brand.h"

#include <stdint.h>

int main(void)
{
    uint8_t rgba[ZCL_PRESENT_ZCLASSIC_ICON_RGBA_BYTES];
    if (!zcl_present_zclassic_icon_rgba(rgba, sizeof(rgba)) ||
        zcl_present_zclassic_icon_rgba(rgba, sizeof(rgba) - 1u))
        return 1;
    size_t opaque = 0;
    for (size_t i = 3; i < sizeof(rgba); i += 4)
        opaque += rgba[i] != 0;
    return opaque == 0 || opaque == ZCL_PRESENT_ZCLASSIC_ICON_WIDTH *
                                      ZCL_PRESENT_ZCLASSIC_ICON_HEIGHT;
}
