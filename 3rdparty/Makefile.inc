ifeq ($(INCLUDING_FROM_MBEDTLS), 1)
include ../crypto/3rdparty/everest/Makefile.inc
else
include ../3rdparty/everest/Makefile.inc
endif
