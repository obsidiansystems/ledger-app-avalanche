ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif
include $(BOLOS_SDK)/Makefile.defines

APPNAME = "Avalanche"

APP_LOAD_PARAMS= --appFlags 0 --curve secp216k1 --path "44'/9000'" --path "44'/60'" $(COMMON_LOAD_PARAMS)

GIT_DESCRIBE ?= $(shell git describe --tags --abbrev=8 --always --long --dirty 2>/dev/null)

VERSION_TAG ?= $(shell echo "$(GIT_DESCRIBE)" | cut -f1 -d-)
APPVERSION_M=0
APPVERSION_N=6
APPVERSION_P=0
APPVERSION=$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)

# Only warn about version tags if specified/inferred
#ifeq ($(VERSION_TAG),)
#  $(warning VERSION_TAG not checked)
#else
#  ifneq (v$(APPVERSION), $(VERSION_TAG))
#    $(warning Version-Tag Mismatch: v$(APPVERSION) version and $(VERSION_TAG) tag)
#  endif
#endif

COMMIT ?= $(shell echo "$(GIT_DESCRIBE)" | sed 's/-dirty/*/')
ifeq ($(COMMIT),)
  $(warning COMMIT not specified and could not be determined with git from "$(GIT_DESCRIBE)")
else
  $(info COMMIT=$(COMMIT))
endif

ifeq ($(TARGET_NAME),TARGET_NANOS)
ICONNAME=icons/nano-s.gif
else
ICONNAME=icons/nano-x.gif
endif

##############
# Chunk size #
##############

PROMPT_MAX_BATCH_SIZE = 1

DEFINES   += PROMPT_MAX_BATCH_SIZE=$(PROMPT_MAX_BATCH_SIZE)

################
# Default rule #
################
all: show-app default


.PHONY: show-app
show-app:
	@echo ">>>>> Building $(APP) at commit $(COMMIT)"


############
# Platform #
############

DEFINES   += OS_IO_SEPROXYHAL
DEFINES   += HAVE_BAGL HAVE_SPRINTF
DEFINES   += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=6 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES   += HAVE_LEGACY_PID
DEFINES   += VERSION=\"$(APPVERSION)\" APPVERSION_M=$(APPVERSION_M)
DEFINES   += COMMIT=\"$(COMMIT)\" APPVERSION_N=$(APPVERSION_N) APPVERSION_P=$(APPVERSION_P)
# DEFINES   += _Static_assert\(...\)=

ifeq ($(TARGET_NAME),TARGET_NANOX)
APP_LOAD_PARAMS += --appFlags 0x240 # with BLE support
DEFINES   += HAVE_BLE BLE_COMMAND_TIMEOUT_MS=2000
DEFINES   += HAVE_BLE_APDU # basic ledger apdu transport over BLE

SDK_SOURCE_PATH  += lib_blewbxx lib_blewbxx_impl
endif

ifeq ($(TARGET_NAME),TARGET_NANOS)
DEFINES   += IO_SEPROXYHAL_BUFFER_SIZE_B=128
DEFINES   += HAVE_UX_FLOW
else
DEFINES   += IO_SEPROXYHAL_BUFFER_SIZE_B=300
DEFINES   += HAVE_GLO096 HAVE_UX_FLOW
DEFINES   += HAVE_BAGL BAGL_WIDTH=128 BAGL_HEIGHT=64
DEFINES   += HAVE_BAGL_ELLIPSIS # long label truncation feature
DEFINES   += HAVE_BAGL_FONT_OPEN_SANS_REGULAR_11PX
DEFINES   += HAVE_BAGL_FONT_OPEN_SANS_EXTRABOLD_11PX
DEFINES   += HAVE_BAGL_FONT_OPEN_SANS_LIGHT_16PX
endif

# Enabling debug PRINTF
DEBUG ?= 0
ifneq ($(DEBUG),0)

        DEFINES += AVA_DEBUG
        DEFINES += STACK_MEASURE

        ifeq ($(TARGET_NAME),TARGET_NANOS)
                DEFINES   += HAVE_PRINTF PRINTF=screen_printf
        else
                DEFINES   += HAVE_PRINTF PRINTF=mcu_usb_printf
        endif
else
        DEFINES   += PRINTF\(...\)=
endif



##############
# Compiler #
##############

ifneq ($(BOLOS_ENV),)
$(info BOLOS_ENV=$(BOLOS_ENV))
CLANGPATH := $(BOLOS_ENV)/clang-arm-fropi/bin/
GCCPATH := $(BOLOS_ENV)/gcc-arm-none-eabi-5_3-2016q1/bin/
CFLAGS += -idirafter $(BOLOS_ENV)/gcc-arm-none-eabi-5_3-2016q1/arm-none-eabi/include
else
$(info BOLOS_ENV is not set: falling back to CLANGPATH and GCCPATH)
endif

ifeq ($(CLANGPATH),)
$(info CLANGPATH is not set: clang will be used from PATH)
endif
ifeq ($(GCCPATH),)
$(info GCCPATH is not set: $(TOOL_PREFIX)* will be used from PATH)
endif

ifneq ($(USE_NIX),)
## asssume Nix toolchain for now
# More specific toolchain prefix
TOOL_PREFIX = armv6m-unknown-none-eabi-
# no sysroots with Nix, empty on purpose
USE_SYSROOT =
else
# Will not be defined if using SDK without our PR.
TOOL_PREFIX ?= arm-none-eabi-
# Need to override defaults harder, ?= will not work here.
CC       := $(CLANGPATH)clang
AS       := $(GCCPATH)$(TOOL_PREFIX)gcc
endif

CFLAGS   += -O3 -Os -Wall -Wextra -Wimplicit-fallthrough
ifneq ($(USE_NIX),)
CFLAGS   += -mcpu=sc000
endif

LD       := $(GCCPATH)$(TOOL_PREFIX)gcc
LDFLAGS  += -O3 -Os
ifneq ($(USE_NIX),)
LDFLAGS  += -mcpu=sc000
endif
LDLIBS   += -lm -lgcc -lc

# import rules to compile glyphs(/pone)
include $(BOLOS_SDK)/Makefile.glyphs

### computed variables
APP_SOURCE_PATH  += src
SDK_SOURCE_PATH  += lib_stusb lib_stusb_impl
SDK_SOURCE_PATH  += lib_ux

### U2F support (wallet app only)
SDK_SOURCE_PATH  += lib_u2f

DEFINES   += USB_SEGMENT_SIZE=64
# Need to use the same magic as the eth app; else metamask (which still uses u2f) won't see us.
DEFINES   += U2F_PROXY_MAGIC=\"w0w\"
DEFINES   += HAVE_IO_U2F HAVE_U2F

### WebUSB support
DEFINES   += HAVE_WEBUSB WEBUSB_URL_SIZE_B=0 WEBUSB_URL=""

load: all
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

delete:
	python -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

# import generic rules from the sdk
include $(BOLOS_SDK)/Makefile.rules

#add dependency on custom makefile filename
dep/%.d: %.c Makefile

.PHONY: test test-no-nix watch watch-test

watch:
	ls Makefile src/*.c src/*.h | entr -cr $(MAKE)

watch-test:
	ls Makefile src/*.c src/*.h tests/*.ts tests/deps/hw-app-avalanche/src/*.ts | entr -cr $(MAKE) test

test: tests/*.ts tests/package.json bin/app.elf
	LEDGER_APP=bin/app.elf \
		PROMPT_MAX_BATCH_SIZE=$(PROMPT_MAX_BATCH_SIZE) \
		mocha-wrapper tests

test-no-nix: tests/node_packages tests/*.ts tests/package.json bin/app.elf
	(cd tests; yarn test)

tests/node_packages: tests/package.json
	(cd tests; yarn install --frozen-lockfile)

listvariants:
	@echo VARIANTS COIN AVAX
