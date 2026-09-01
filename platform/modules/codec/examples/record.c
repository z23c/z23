/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "codec/cursor.h"

int main(void)
{
    unsigned char wire[10];
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, wire, sizeof(wire));
    return zcl_codec_write_u16le(&writer, 23) &&
           zcl_codec_write_u64le(&writer, 42) ? 0 : 1;
}
