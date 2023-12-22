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
