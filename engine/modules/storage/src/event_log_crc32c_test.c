/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Test adapters for the shared CRC32C implementation. */
#include "storage/event_log.h"
#include "util/crc32c.h"

#ifdef ZCL_TESTING
const char *event_log_crc32c_impl(void) { return zcl_crc32c_impl_name(); }
uint32_t event_log_crc32c_test_sw(const void *data, size_t len)
{ return zcl_crc32c_sw(data, len); }
uint32_t event_log_crc32c_test_active(const void *data, size_t len)
{ return zcl_crc32c(data, len); }
bool event_log_crc32c_hw_available(void) { return zcl_crc32c_hw_available(); }
#else
typedef int event_log_crc32c_test_requires_a_translation_unit;
#endif
