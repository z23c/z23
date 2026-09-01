# platform/ports/ — Hexagonal interface contracts

This directory holds **port interfaces** in the Clean Architecture /
Hexagonal sense. A port is a thin C struct of function pointers plus a
`void *self` slot. The domain (`domain/`) and use cases
(`engine/application/`) call ports; adapters (`platform/adapters/outbound/`) implement
them.

The dependency rule:

```
domain/, engine/application/  ──depends on──►  platform/ports/  ◄──depends on──  platform/adapters/
```

Nothing in `platform/ports/` may include from `domain/`, `engine/application/`, `app/`,
`core/modules/net/`, `engine/modules/storage/`, or any adapter. Headers in this directory
are pure C types and function-pointer tables — they declare a contract
without committing to an implementation.

## Convention

Every port header declares:

```c
struct <name>_port {
    void *self;                    /* opaque handle owned by the adapter */
    /* function pointers — first argument is always self */
    zcl_result (*op_a)(void *self, ...);
    ...
};
```

An adapter instantiates a `struct <name>_port` value and hands it to
the domain/application. The domain never knows whether the adapter is
real, in-memory, or simulated.

## Header naming and inclusion

- One port per header: `<name>_port.h`.
- Include guard: `ZCL_PORTS_<NAME>_PORT_H`.
- All ports compile under `-std=c23 -Wall -Wextra -Werror -pedantic`.

## Current ports (Epoch I)

| Header                  | Purpose                                      |
| ----------------------- | -------------------------------------------- |
| `block_log_port.h`      | Append-only block log; content-addressed     |
| `utxo_snapshot_port.h`  | UTXO set with single-writer mutation         |
| `consensus_log_port.h`  | Audit log of accept/reject decisions         |
| `clock_port.h`          | Injectable monotonic + wall clock            |
| `event_emitter_port.h`  | Domain event publishing                      |

Adapters that implement these will land in `platform/adapters/outbound/` in
later sub-steps.
