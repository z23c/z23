<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# vendor/

Pinned third-party code. Do not edit it. Each directory records its source (`SOURCE` or `provenance/*.manifest`) and keeps its upstream license. Local deviations exist only as patches in `patches/`.

Rules:
- Upgrades or patches need an updated provenance record and one non-author review.
- `tor/`, `zclassic-ref/`, `.cache/` and `.build/` are fetched by `make vendor`; they are not source of this repository.
- Do not search vendor trees for project behavior; project code never lives here.
- Never copy vendor code into first-party directories.

Check: `make lint-fast`.
