/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_NET_NET_FAULT_H
#define ZCL_NET_NET_FAULT_H

#include <stdbool.h>
#include <stdint.h>

void net_partition_until_unix(int64_t until_unix);
void net_partition_clear(void);
int64_t net_partition_armed_until_unix(void);
bool net_partition_active_at(int64_t now_unix);

#endif /* ZCL_NET_NET_FAULT_H */
