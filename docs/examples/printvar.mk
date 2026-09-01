# Tiny helper: `include`s the root Makefile and exposes a `print-VAR` target
# so docs/examples/Makefile can read the root build's flags/object lists without
# duplicating them (and without editing the root Makefile). Invoked as:
#   make -s -C .. -f <abspath>/printvar.mk print-VARNAME
include Makefile
print-%:
	@echo '$($*)'
