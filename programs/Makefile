
# To compile on SunOS: add "-lsocket -lnsl" to LDFLAGS

CFLAGS	?= -O2
WARNING_CFLAGS ?= -Wall -Wextra -Wformat=2 -Wno-format-nonliteral
WARNING_CXXFLAGS ?= -Wall -Wextra -Wformat=2 -Wno-format-nonliteral
LDFLAGS ?=

MBEDTLS_TEST_PATH:=../tests/src
MBEDTLS_TEST_OBJS:=$(patsubst %.c,%.o,$(wildcard ${MBEDTLS_TEST_PATH}/*.c ${MBEDTLS_TEST_PATH}/drivers/*.c))

LOCAL_CFLAGS = $(WARNING_CFLAGS) -I../tests/include -I../include -D_FILE_OFFSET_BITS=64
LOCAL_CXXFLAGS = $(WARNING_CXXFLAGS) -I../include -I../tests/include -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS = ${MBEDTLS_TEST_OBJS} 		\
		-L../library 			\
		-lmbedtls$(SHARED_SUFFIX)	\
		-lmbedx509$(SHARED_SUFFIX)	\
		-lmbedcrypto$(SHARED_SUFFIX)

ifeq ($(shell uname -s),Linux)
DLOPEN_LDFLAGS ?= -ldl
else
DLOPEN_LDFLAGS ?=
endif

include ../3rdparty/Makefile.inc
LOCAL_CFLAGS+=$(THIRDPARTY_INCLUDES)

ifndef SHARED
MBEDLIBS=../library/libmbedcrypto.a ../library/libmbedx509.a ../library/libmbedtls.a
else
MBEDLIBS=../library/libmbedcrypto.$(DLEXT) ../library/libmbedx509.$(DLEXT) ../library/libmbedtls.$(DLEXT)
endif
DEP=${MBEDLIBS} ${MBEDTLS_TEST_OBJS}

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
LOCAL_LDFLAGS += -lws2_32
ifdef SHARED
SHARED_SUFFIX=.$(DLEXT)
endif
else
DLEXT ?= so
EXEXT=
SHARED_SUFFIX=
endif

ifdef WINDOWS
PYTHON ?= python
else
PYTHON ?= $(shell if type python3 >/dev/null 2>/dev/null; then echo python3; else echo python; fi)
endif

# Only build the dlopen test in shared library builds, and not when building
# for Windows.
ifdef BUILD_DLOPEN
# Don't override the value
else ifdef WINDOWS_BUILD
BUILD_DLOPEN =
else ifdef SHARED
BUILD_DLOPEN = y
else
BUILD_DLOPEN =
endif

## The following assignment is the list of base names of applications that
## will be built on Windows. Extra Linux/Unix/POSIX-only applications can
## be declared by appending with `APPS += ...` afterwards.
## See the get_app_list function in scripts/generate_visualc_files.pl and
## make sure to check that it still works if you tweak the format here.
APPS = \
	aes/crypt_and_hash \
	cipher/cipher_aead_demo \
	hash/generic_sum \
	hash/hello \
	hash/md_hmac_demo \
	pkey/dh_client \
	pkey/dh_genprime \
	pkey/dh_server \
	pkey/ecdh_curve25519 \
	pkey/ecdsa \
	pkey/gen_key \
	pkey/key_app \
	pkey/key_app_writer \
	pkey/mpi_demo \
	pkey/pk_decrypt \
	pkey/pk_encrypt \
	pkey/pk_sign \
	pkey/pk_verify \
	pkey/rsa_decrypt \
	pkey/rsa_encrypt \
	pkey/rsa_genkey \
	pkey/rsa_sign \
	pkey/rsa_sign_pss \
	pkey/rsa_verify \
	pkey/rsa_verify_pss \
	psa/aead_demo \
	psa/crypto_examples \
	psa/hmac_demo \
	psa/key_ladder_demo \
	psa/psa_constant_names \
	random/gen_entropy \
	random/gen_random_ctr_drbg \
	ssl/dtls_client \
	ssl/dtls_server \
	ssl/mini_client \
	ssl/ssl_client1 \
	ssl/ssl_client2 \
	ssl/ssl_context_info \
	ssl/ssl_fork_server \
	ssl/ssl_mail_client \
	ssl/ssl_server \
	ssl/ssl_server2 \
	test/benchmark \
	test/query_compile_time_config \
	test/selftest \
	test/udp_proxy \
	test/zeroize \
	util/pem2der \
	util/strerror \
	x509/cert_app \
	x509/cert_req \
	x509/cert_write \
	x509/crl_app \
	x509/load_roots \
	x509/req_app \
# End of APPS

ifdef PTHREAD
APPS +=	ssl/ssl_pthread_server
endif

ifdef BUILD_DLOPEN
APPS +=	test/dlopen
endif

ifdef TEST_CPP
APPS += test/cpp_dummy_build
endif

EXES = $(patsubst %,%$(EXEXT),$(APPS))

.SILENT:

.PHONY: all clean list fuzz

all: $(EXES)
ifndef WINDOWS
# APPS doesn't include the fuzzing programs, which aren't "normal"
# sample or test programs, and don't build with MSVC which is
# warning about fopen
all: fuzz
endif

fuzz: ${MBEDTLS_TEST_OBJS}
	$(MAKE) -C fuzz THIRDPARTY_INCLUDES=$(THIRDPARTY_INCLUDES)

$(MBEDLIBS):
	$(MAKE) -C ../library

${MBEDTLS_TEST_OBJS}:
	$(MAKE) -C ../tests mbedtls_test

.PHONY: generated_files
GENERATED_FILES = psa/psa_constant_names_generated.c test/query_config.c
generated_files: $(GENERATED_FILES)

psa/psa_constant_names_generated.c: ../scripts/generate_psa_constants.py
psa/psa_constant_names_generated.c: ../include/psa/crypto_values.h
psa/psa_constant_names_generated.c: ../include/psa/crypto_extra.h
psa/psa_constant_names_generated.c: ../tests/suites/test_suite_psa_crypto_metadata.data
psa/psa_constant_names_generated.c:
	echo "  Gen   $@"
	$(PYTHON) ../scripts/generate_psa_constants.py

test/query_config.c: ../scripts/generate_query_config.pl
## The generated file only depends on the options that are present in mbedtls_config.h,
## not on which options are set. To avoid regenerating this file all the time
## when switching between configurations, don't declare mbedtls_config.h as a
## dependency. Remove this file from your working tree if you've just added or
## removed an option in mbedtls_config.h.
#test/query_config.c: ../include/mbedtls/mbedtls_config.h
test/query_config.c: ../scripts/data_files/query_config.fmt
test/query_config.c:
	echo "  Gen   $@"
	$(PERL) ../scripts/generate_query_config.pl

.c.o:
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -o $@ -c $<

.cpp.o:
	echo "  CXX   $<"
	$(CXX) $(LOCAL_CXXFLAGS) $(CXXFLAGS) -o $@ -c $<

$(EXES): %$(EXEXT): %.o $(DEP)
	echo "  LD    $@"
	$(CC) $(filter-out $(DEP),$^) $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

psa/psa_constant_names.o: psa/psa_constant_names_generated.c

SSL_TEST_OBJECTS = test/query_config.o ssl/ssl_test_lib.o
SSL_TEST_DEPS = test/query_config.h \
		ssl/ssl_test_lib.h \
		ssl/ssl_test_common_source.c

ssl/ssl_test_lib.o: ssl/ssl_test_lib.h

ssl/ssl_client2.o ssl/ssl_server2.o: $(SSL_TEST_DEPS)
ssl/ssl_client2$(EXEXT) ssl/ssl_server2$(EXEXT): $(SSL_TEST_OBJECTS)

ssl/ssl_context_info.o: test/query_config.h
ssl/ssl_context_info$(EXEXT): test/query_config.o

test/cpp_dummy_build.cpp: test/generate_cpp_dummy_build.sh
	echo "  Gen   test/cpp_dummy_build.cpp"
	test/generate_cpp_dummy_build.sh

# Do not link any test objects (that would bring in a static dependency on
# libmbedcrypto at least). Do not link with libmbed* (that would defeat the
# purpose of testing dynamic loading).
test/dlopen$(EXEXT): LOCAL_LDFLAGS =
test/dlopen$(EXEXT): LDFLAGS += $(DLOPEN_LDFLAGS)

test/query_config.o: test/query_config.h

test/query_compile_time_config.o: test/query_config.h
test/query_compile_time_config$(EXEXT): test/query_config.o

CLEANOBJS := $(patsubst %,%*.o,$(sort $(dir $(APPS))))
clean:
ifndef WINDOWS
	rm -f $(EXES) $(CLEANOBJS)
	-rm -f ssl/ssl_pthread_server$(EXEXT)
	-rm -f test/cpp_dummy_build.cpp test/cpp_dummy_build$(EXEXT)
	-rm -f test/dlopen$(EXEXT)
else
	for %%f in ($(subst /,\,$(CLEANOBJS) $(patsubst %o,%exe,$(CLEANOBJS)))) do del /Q /F %%f
	if exist test\cpp_dummy_build.cpp del /Q /F test\cpp_dummy_build.cpp
endif
	$(MAKE) -C fuzz clean

neat: clean
ifndef WINDOWS
	rm -f $(GENERATED_FILES)
else
	for %%f in ($(subst /,\,$(GENERATED_FILES))) do if exist %%f del /Q /F %%f
endif

list:
	echo $(EXES)
