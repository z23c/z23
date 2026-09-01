#include "encoding/utilstrencodings.h"

#include <stdint.h>
#include <string.h>

int main(void)
{
    static const uint8_t bytes[] = {0x00, 0x7f, 0xa5, 0xff};
    char hex[16], base64[16];
    uint8_t decoded[8];
    bool invalid = true;
    HexStr(bytes, sizeof(bytes), false, hex, sizeof(hex));
    if (strcmp(hex, "007fa5ff") != 0 || !IsHex(hex) ||
        ParseHex(hex, decoded, sizeof(decoded)) != sizeof(bytes) ||
        memcmp(bytes, decoded, sizeof(bytes)) != 0)
        return 1;
    if (EncodeBase64(bytes, sizeof(bytes), base64, sizeof(base64)) == 0 ||
        DecodeBase64(base64, decoded, sizeof(decoded), &invalid) !=
            sizeof(bytes) || invalid || memcmp(bytes, decoded, sizeof(bytes)))
        return 2;
    return 0;
}
