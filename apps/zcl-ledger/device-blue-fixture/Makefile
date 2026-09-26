# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
ifndef BOLOS_SDK
$(error BOLOS_SDK is required)
endif
ifndef ARM_INCLUDE_DIR
$(error ARM_INCLUDE_DIR is required)
endif
include $(BOLOS_SDK)/Makefile.defines

ifneq ($(TARGET_ID),0x31000004)
$(error The SDK must target Ledger Blue firmware 2.1.x)
endif

APPNAME = "ZCL Fixture"
APPVERSION = 0.1.0
APP_FLAGS = 0x00
APP_SOURCE_PATH += src
SDK_SOURCE_PATH += lib_stusb lib_stusb_impl

DEFINES += OS_IO_SEPROXYHAL IO_SEPROXYHAL_BUFFER_SIZE_B=128
DEFINES += HAVE_BAGL HAVE_IO_USB HAVE_L4_USBLIB
DEFINES += IO_USB_MAX_ENDPOINTS=7 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES += CX_COMPLIANCE_141

CC := $(CLANGPATH)clang
AS := $(GCCPATH)arm-none-eabi-gcc
LD := $(GCCPATH)arm-none-eabi-gcc
CFLAGS += -std=c23 -O2 -Wall -Wextra -Werror -pedantic
LDFLAGS += -O2 -Wl,-z,noexecstack
LDLIBS += -lgcc -lc

all: default check-image

include $(BOLOS_SDK)/Makefile.rules

check-image: default
	@data_size=$$($(GCCPATH)arm-none-eabi-size -A bin/app.elf | awk '$$1 == ".data" { print $$2 }'); \
	  test "$$data_size" = 0 || { echo "Initialized .data requires loader allocation; refusing image" >&2; exit 1; }
