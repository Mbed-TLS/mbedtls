# To compile on SunOS: add "-lsocket -lnsl" to LDFLAGS

CFLAGS	?= -O2
WARNING_CFLAGS ?= -Wall -Wextra -Wformat=2 -Wno-format-nonliteral
WARNING_CXXFLAGS ?= -Wall -Wextra -Wformat=2 -Wno-format-nonliteral
LDFLAGS ?=

LOCAL_CFLAGS = $(WARNING_CFLAGS) -I../tests/include -I../include -D_FILE_OFFSET_BITS=64
LOCAL_CXXFLAGS = $(WARNING_CXXFLAGS) -I../include -I../tests/include -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS = ${MBEDTLS_TEST_OBJS} 		\
		-L../library			\
		-lmbedtls$(SHARED_SUFFIX)	\
		-lmbedx509$(SHARED_SUFFIX)	\
		-lmbedcrypto$(SHARED_SUFFIX)

include ../3rdparty/Makefile.inc
LOCAL_CFLAGS+=$(THIRDPARTY_INCLUDES)

ifndef SHARED
MBEDLIBS=../library/libmbedcrypto.a ../library/libmbedx509.a ../library/libmbedtls.a
else
MBEDLIBS=../library/libmbedcrypto.$(DLEXT) ../library/libmbedx509.$(DLEXT) ../library/libmbedtls.$(DLEXT)
endif

ifdef DEBUG
LOCAL_CFLAGS += -g3
endif

# if we're running on Windows, build for Windows
ifdef WINDOWS
WINDOWS_BUILD=1
endif

## Usage: $(call remove_unset_options,PREPROCESSOR_INPUT)
## Remove the preprocessor symbols that are not set in the current configuration
## from PREPROCESSOR_INPUT. Also normalize whitespace.
## Example:
##   $(call remove_unset_options,MBEDTLS_FOO MBEDTLS_BAR)
## This expands to an empty string "" if MBEDTLS_FOO and MBEDTLS_BAR are both
## disabled, to "MBEDTLS_FOO" if MBEDTLS_BAR is enabled but MBEDTLS_FOO is
## disabled, etc.
##
## This only works with a Unix-like shell environment (Bourne/POSIX-style shell
## and standard commands) and a Unix-like compiler (supporting -E). In
## other environments, the output is likely to be empty.
define remove_unset_options
$(strip $(shell
  exec 2>/dev/null;
  { echo '#include <mbedtls/build_info.h>'; echo $(1); } |
  $(CC) $(LOCAL_CFLAGS) $(CFLAGS) -E - |
  tail -n 1
))
endef

ifdef WINDOWS_BUILD
  DLEXT=dll
  EXEXT=.exe
  LOCAL_LDFLAGS += -lws2_32 -lbcrypt
  ifdef SHARED
    SHARED_SUFFIX=.$(DLEXT)
  endif

else # Not building for Windows
  DLEXT ?= so
  EXEXT=
  SHARED_SUFFIX=
  ifndef THREADING
    # Auto-detect configurations with pthread.
    # If the call to remove_unset_options returns "control", the symbols
    # are confirmed set and we link with pthread.
    # If the auto-detection fails, the result of the call is empty and
    # we keep THREADING undefined.
    ifeq (control,$(call remove_unset_options,control MBEDTLS_THREADING_C MBEDTLS_THREADING_PTHREAD))
      THREADING := pthread
    endif
  endif

  ifeq ($(THREADING),pthread)
    LOCAL_LDFLAGS += -lpthread
  endif
endif

ifdef WINDOWS
PYTHON ?= python
else
PYTHON ?= $(shell if type python3 >/dev/null 2>/dev/null; then echo python3; else echo python; fi)
endif

# See root Makefile
GEN_FILES ?= yes
ifdef GEN_FILES
gen_file_dep =
else
gen_file_dep = |
endif

default: all

$(MBEDLIBS):
	$(MAKE) -C ../library

neat: clean
ifndef WINDOWS
	rm -f $(GENERATED_FILES)
else
	for %f in ($(subst /,\,$(GENERATED_FILES))) if exist %f del /Q /F %f
endif
