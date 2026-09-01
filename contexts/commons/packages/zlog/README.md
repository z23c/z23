# zlog

Small leveled logging sink for C23.

- Six levels (trace..error, plus off) with per-sink thresholds.
- Caller-injected `emit` callback — no stdio dependency in the core.
- Bounded line assembly: "LEVEL tag message\n", long messages and tags
  truncated, never overrun.
- Optional subsystem tag per sink.

## API

```c
#include <zlog/zlog.h>

static void emit(void *ctx, const char *line) { fputs(line, stderr); }

zlog_sink log = { emit, NULL, ZLOG_INFO, true, "net" };
zlog_info(&log, "peer connected");
zlog_warn(&log, "retrying");
```

## CLI

```sh
zlog -t net -l debug info "peer connected"
zlog warn "low disk"
```

## License

Apache-2.0. See LICENSE.
