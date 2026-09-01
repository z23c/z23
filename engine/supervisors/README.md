# engine/supervisors/

**Shape:** Supervisor — declared liveness tree with restart/stall policy.

Each source file in `src/` owns one supervisor domain or one narrow liveness
registration surface. Supervisors register `struct liveness_contract` children
through `platform/modules/util/include/util/supervisor.h`, grouped by domain in `domains.c`.

Current roots include network, chain, staged-sync, legacy-mirror, and
self-heal/condition-engine liveness. Boot still wires lifecycle dependencies,
so this shape is partial; do not add placeholder roots or macro-only scaffold.
A supervisor file should make a running child visible through the root
liveness tree or it should not exist.

What is still in `engine/composition/src/boot_services.c` is the ORDER the registrars run
in, not the registrations themselves: every other long-running service owns
its own `liveness_contract` in its own file. That order is load-bearing (the
tip watchdog before the escalator, the escalator before self-heal) and is
pinned by ordering asserts in `tests/harness/src/test_make_lint_gates.c`, so it
moves under a seam design, never as a code-motion sweep.

See [`docs/FRAMEWORK.md`](../../docs/FRAMEWORK.md) for the destination shape
and its §9 debt board for remaining supervisor cleanup.
