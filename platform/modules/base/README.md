# zclassic23/base

The dependency-sink package for ZClassic23 C23 modules. It provides bounded
hex and fixed-width byte-order codecs, checked arithmetic, result/logging and
allocation helpers, text fitting, and the canonical memory cleanse primitive.

Public headers live in `include/base/`; implementations live in `src/`.
The package has no dependencies. Build its hermetic test with
`make zcode-package-base-test` from the repository root.
