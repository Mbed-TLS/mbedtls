EVEREST_ENABLED=$(shell perl ../scripts/config.pl -f ../include/mbedtls/config.h get MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED; echo $$?)

ifeq ($(EVEREST_ENABLED),0)
THIRDPARTY_INCLUDES+=-I../3rdparty/everest/include -I../3rdparty/everest/include/everest -I../3rdparty/everest/include/everest/kremlib

THIRDPARTY_CRYPTO_OBJECTS+= \
	../3rdparty/everest/library/everest.o \
	../3rdparty/everest/library/x25519.o \
	../3rdparty/everest/library/kremlib/FStar_UInt64_FStar_UInt32_FStar_UInt16_FStar_UInt8.o

ifeq ($(shell getconf LONG_BIT),64)
THIRDPARTY_CRYPTO_OBJECTS+=../3rdparty/everest/library/Hacl_Curve25519.o
else
LOCAL_CFLAGS+="-DKRML_VERIFIED_UINT128"
THIRDPARTY_CRYPTO_OBJECTS+=../3rdparty/everest/library/legacy/Hacl_Curve25519.o \
	../3rdparty/everest/library/kremlib/FStar_UInt128_extracted.o
endif
endif

