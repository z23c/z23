# Services Layer

`engine/services` is the application orchestration layer.

Use it for:

- sync workflows
- snapshot lifecycle
- wallet indexing/rescan orchestration
- health/status aggregation
- explorer query aggregation
- peer policy

Do not use it for:

- raw P2P protocol parsing
- consensus rules
- direct HTML/JSON rendering
- route dispatch

Primary architecture reference: [docs/ARCHITECTURE_DIAGRAMS.md](../../docs/ARCHITECTURE_DIAGRAMS.md)
